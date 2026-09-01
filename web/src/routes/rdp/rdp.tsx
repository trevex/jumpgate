/**
 * rdp.tsx — full-screen in-browser RDP client.
 *
 * A chromeless, own-layout page (rendered OUTSIDE the AppShell): a slim top
 * bar (asset label + connection-status pill + close button) above the
 * Devolutions `<iron-remote-desktop>` web component, which owns its own shadow
 * DOM + `<canvas>` and speaks RDCleanPath to the worker.
 *
 * Flow on mount:
 *   1. Mount the <iron-remote-desktop> element, set its `module` PROPERTY to the
 *      RDP Backend, and `init('INFO')` the wasm once (module-global guard).
 *   2. On the element's `ready` event, mint a session
 *      (CreateRDPSession → {ticket, gatewayEndpoint, insecure}) and connect via
 *      the UserInteraction's ConfigBuilder. The worker is an RDCleanPath gateway
 *      that injects the vault credential server-side, so we connect credential-
 *      less (empty user/pass) with CredSSP disabled (TLS-only Client Info path).
 *   3. Lifecycle is promise-driven — there is no frame counter / DOM connect
 *      event: connect() resolving = connected; rejecting = error (IronError);
 *      info.run() resolving = session ended (closed); rejecting = dropped.
 *
 * Reconnect is explicit (a fresh ticket must be minted); no auto-reconnect.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useParams, useSearchParams, useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@connectrpc/connect-query";
import { X, RotateCw, Loader2, Monitor } from "lucide-react";
import "@devolutions/iron-remote-desktop";
import type { IronError, UserInteraction } from "@devolutions/iron-remote-desktop";
import { Backend, init, enableCredssp } from "@devolutions/iron-remote-desktop-rdp";
import { createRDPSession } from "@/gen/jumpgate/session/v1/session-SessionService_connectquery";
import { getAssetDisplay } from "@/gen/jumpgate/catalog/v1/catalog-CatalogService_connectquery";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { connectErrorMessage } from "@/lib/format";

// ─── Connection status ────────────────────────────────────────────────────────

type Status =
  | { kind: "connecting" }
  | { kind: "connected" }
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
  closed: {
    label: "Session ended",
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

// ─── wasm bootstrap: init() exactly once per page load ──────────────────────────

let wasmReady: Promise<void> | null = null;
function ensureWasm(): Promise<void> {
  if (!wasmReady) wasmReady = init("INFO");
  return wasmReady;
}

// The <iron-remote-desktop> element exposes a settable `module` property (the
// protocol Backend). Minimal handle so we can set it without fighting the
// custom-element JSX typing.
type IronElement = HTMLElement & { module: unknown };

function isIronError(err: unknown): err is IronError {
  return typeof (err as Partial<IronError>)?.kind === "function";
}

// IronErrorKind is type-only in the shipped JS (no runtime enum export), so map
// its numeric values (see @devolutions/iron-remote-desktop index.d.ts) by hand.
const IRON_ERR_KIND: Record<number, string> = {
  0: "general error",
  1: "wrong password",
  2: "logon failure",
  3: "access denied",
  4: "RDCleanPath error",
  5: "proxy connect failed",
  6: "negotiation failure",
};

function errMessage(err: unknown): string {
  if (isIronError(err)) {
    const k = err.kind();
    return IRON_ERR_KIND[k] ?? `error ${k}`;
  }
  return connectErrorMessage(err);
}

// ─── RDP page ─────────────────────────────────────────────────────────────────

export function RdpPage() {
  const { assetId = "" } = useParams<{ assetId: string }>();
  const [searchParams] = useSearchParams();
  const login = searchParams.get("login") ?? "";
  const navigate = useNavigate();

  const hostRef = useRef<HTMLDivElement | null>(null);

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

  // ponytail: e2e-only liveness hook. The component paints RDP into its own
  // shadow-DOM canvas (not scrapeable renderer-agnostically), and there is no
  // frame counter / DOM connect event — status is promise-driven. Mirror the
  // React status so web/e2e/rdp.spec.ts can assert the session stays connected.
  useEffect(() => {
    (window as unknown as { __jumpgateRdp?: { status: Status["kind"] } }).__jumpgateRdp = {
      status: status.kind,
    };
  }, [status]);

  // ─── Connect: mount element → ready → mint ticket → connect ──────────────────
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    let disposed = false;
    let ui: UserInteraction | null = null;

    const el = document.createElement("iron-remote-desktop") as IronElement;
    el.setAttribute("scale", "fit");
    el.setAttribute("flexcenter", "true");
    el.style.width = "100%";
    el.style.height = "100%";
    el.module = Backend;

    const onReady = async (ev: Event) => {
      ui = (ev as CustomEvent<{ irgUserInteraction: UserInteraction }>).detail.irgUserInteraction;
      try {
        await ensureWasm();
        if (disposed) return;

        const resp = await createSession({
          assetId,
          login,
          insecure: window.location.protocol === "http:",
        });
        if (disposed) return;

        const scheme = resp.insecure ? "ws" : "wss";
        const proxyAddress = `${scheme}://${resp.gatewayEndpoint}/rdp?ticket=${encodeURIComponent(resp.ticket)}`;
        const config = ui
          .configBuilder()
          .withProxyAddress(proxyAddress)
          .withDestination("injected:3389") // worker ignores destination (uses warden target); build() only needs non-empty
          .withAuthToken(resp.ticket) // gateway auths off ?ticket=; builder just requires non-empty
          .withUsername("") // credential-less — worker injects the vault password
          .withPassword("")
          .withExtension(enableCredssp(false)) // TLS-only (no NLA) → worker's Client Info injection path
          .build();

        ui.onWarningCallback((msg) => console.warn("iron-remote-desktop:", msg));

        const info = await ui.connect(config);
        if (disposed) return;
        setStatus({ kind: "connected" });
        ui.setVisibility(true);

        try {
          await info.run(); // resolves on graceful end, rejects on drop
          if (!disposed) setStatus({ kind: "closed" });
        } catch (err) {
          if (!disposed) setStatus({ kind: "error", message: errMessage(err) });
        }
      } catch (err) {
        if (!disposed) setStatus({ kind: "error", message: errMessage(err) });
      }
    };

    el.addEventListener("ready", onReady);
    host.appendChild(el);

    return () => {
      disposed = true;
      el.removeEventListener("ready", onReady);
      try {
        ui?.shutdown();
      } catch {
        /* element may already be torn down */
      }
      el.remove();
    };
    // Reconnect is explicit via `attempt`; assetId/login are route-stable.
  }, [attempt, assetId, login, createSession]);

  const terminated = status.kind === "closed" || status.kind === "error";

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
      <div className="relative flex min-h-0 flex-1 items-center justify-center overflow-hidden bg-black">
        <div ref={hostRef} className="h-full w-full" />

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
