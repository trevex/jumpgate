package pgproxy

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/trevex/jumpgate/workers/pg-proxy/internal/record"
)

// Splice proxies pgwire bytes both directions until either side closes or cancel
// fires, then closes both conns and returns the SessionEnd reason.
//
// rec == nil (recording disabled) → a plain dual byte-copy, identical to the
// pre-recording behavior.
//
// rec != nil → asymmetric recording, per "audit the user, not the database":
//   - client→target (the user's statements) is decoded frame-by-frame BEFORE being
//     forwarded and is FAIL-CLOSED: a frontend parse error or a recorder failure
//     kills the session ("recording_failed") — no un-recorded statement byte
//     reaches the target.
//   - target→client (outcomes) is forwarded RAW and skimmed best-effort for command
//     tags and errors only; a skim hiccup degrades to plain passthrough and never
//     kills the session, and result-row bytes are never decoded/re-encoded.
//
// be is the client-side Backend from ReadStartup (reused so any bytes it buffered
// past the startup message are not lost). client is the underlying client conn
// (for close); target is the hijacked Postgres conn.
func Splice(be *pgproto3.Backend, client, target net.Conn, cancel <-chan struct{}, rec *record.Recorder, start time.Time) string {
	if rec == nil {
		return spliceRaw(client, target, cancel)
	}
	reason := make(chan string, 2)
	go func() {
		if err := pumpClient(be, target, rec, start); err != nil {
			reason <- "recording_failed"
		} else {
			reason <- "closed"
		}
	}()
	go func() {
		pumpTarget(target, client, rec, start)
		reason <- "closed"
	}()
	var r string
	select {
	case r = <-reason:
	case <-cancel:
		r = "closed"
	}
	_ = client.Close()
	_ = target.Close()
	return r
}

func spliceRaw(client, target net.Conn, cancel <-chan struct{}) string {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	select {
	case <-done:
	case <-cancel:
	}
	_ = client.Close()
	_ = target.Close()
	return "closed"
}

// pumpClient reads frontend messages from the client via be, records the auditable
// ones (fail-closed), and forwards every message to target. Forwarding uses a
// write-only Frontend so re-encoding matches pgproto3's own framing exactly.
func pumpClient(be *pgproto3.Backend, target net.Conn, rec *record.Recorder, start time.Time) error {
	fwd := pgproto3.NewFrontend(target, target) // write-only: Receive is never called
	for {
		msg, err := be.Receive()
		if err != nil {
			if isCleanEnd(err) {
				return nil // client closed the connection (session ending)
			}
			return err // malformed/undecodable mid-stream frame → fail closed
		}
		if ev, ok := frontendEvent(msg, start); ok {
			if err := rec.Tap(ev); err != nil {
				return err // recorder failure → fail closed
			}
		}
		fwd.Send(msg)
		if err := fwd.Flush(); err != nil {
			return nil // target gone → normal end
		}
	}
}

// isCleanEnd reports whether a client-side Receive error means the connection is
// ending rather than a malformed frame. pgproto3's Backend.Receive translates a
// connection close at a message boundary into io.ErrUnexpectedEOF (NOT io.EOF), so a
// normal client disconnect (psql \q, socket close) must be recognized here or every
// successful session would be misreported as "recording_failed". A frame cut short
// by EOF was never fully decoded and so never forwarded to the target — the
// no-un-recorded-byte invariant holds either way. A genuinely malformed frame
// (unknown message type, bad length on a fully-read frame) yields a different error
// and correctly fails closed.
func isCleanEnd(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe)
}

// pumpTarget forwards target→client bytes verbatim while a best-effort skim reads a
// duplicate of the same stream for command tags and errors. It never fails the
// session: a skim decode error just drains the rest and stops recording backend
// events. Result-row bytes flow through untouched (no decode/re-encode).
func pumpTarget(target, client net.Conn, rec *record.Recorder, start time.Time) {
	pr, pw := io.Pipe()
	go skimBackend(pr, rec, start)
	_, _ = io.Copy(client, io.TeeReader(target, pw))
	_ = pw.Close() // EOF the skim
}

func skimBackend(pr *io.PipeReader, rec *record.Recorder, start time.Time) {
	fe := pgproto3.NewFrontend(pr, io.Discard)
	for {
		msg, err := fe.Receive()
		if err != nil {
			// Keep the pipe drained so the TeeReader write in pumpTarget never
			// blocks and stalls forwarding. Best-effort: we stop recording backend
			// events for the rest of the session.
			_, _ = io.Copy(io.Discard, pr)
			return
		}
		if ev, ok := backendEvent(msg, start); ok {
			_ = rec.Tap(ev) // best-effort; backend direction is not fail-closed
		}
	}
}

// frontendEvent maps an auditable client message to a timeline event. Bind logs
// only the PARAMETER COUNT — never the bound values (same PII class as result rows,
// deferred). Parse logs the SQL and param type OIDs (shape, not data).
func frontendEvent(msg pgproto3.FrontendMessage, start time.Time) (record.Event, bool) {
	t := time.Since(start).Milliseconds()
	switch m := msg.(type) {
	case *pgproto3.Query:
		return record.Event{"t": t, "type": "query", "sql": m.String}, true
	case *pgproto3.Parse:
		return record.Event{"t": t, "type": "parse", "name": m.Name, "sql": m.Query, "param_oids": m.ParameterOIDs}, true
	case *pgproto3.Bind:
		return record.Event{"t": t, "type": "bind", "stmt": m.PreparedStatement, "portal": m.DestinationPortal, "params": len(m.Parameters)}, true
	case *pgproto3.Execute:
		return record.Event{"t": t, "type": "execute", "portal": m.Portal}, true
	default:
		return nil, false
	}
}

// backendEvent maps an auditable server message (outcome) to a timeline event.
// ponytail: error Message text can echo a data value (e.g. "Key (ssn)=(...)"); kept
// because a bare SQLSTATE is near-useless to an auditor. Tighten to code+severity
// only if it bites.
func backendEvent(msg pgproto3.BackendMessage, start time.Time) (record.Event, bool) {
	t := time.Since(start).Milliseconds()
	switch m := msg.(type) {
	case *pgproto3.CommandComplete:
		return record.Event{"t": t, "type": "command_complete", "tag": string(m.CommandTag)}, true
	case *pgproto3.ErrorResponse:
		return record.Event{"t": t, "type": "error", "severity": m.Severity, "code": m.Code, "message": m.Message}, true
	default:
		return nil, false
	}
}
