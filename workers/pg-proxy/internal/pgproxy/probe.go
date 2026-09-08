package pgproxy

// Credential-free PostgreSQL TLS host-identity probe + runtime match.
//
// ObserveTarget speaks just enough of the Postgres startup protocol to reach and
// capture the target's TLS identity: it sends the SSLRequest packet, requires the
// server to accept TLS ('S'), completes a TLS handshake capturing the presented
// certificate chain WITHOUT verifying it, and then STOPS — no pg startup/login
// packet is ever sent. A plaintext downgrade ('N') is a hard failure. This is the
// same observation used for onboarding evidence and for per-session verification.
//
// MatchIdentity is the runtime enforcement half: it checks an observed chain
// against the trust anchors PrepareSession returned before any credential is
// released — exact leaf-fingerprint equality for a tls_leaf pin, or full X.509
// chain-to-CA validation plus the configured DNS/IP name for a tls_ca anchor.
//
// Two TLS handshakes hit the target per session: this credential-free observe (to
// authenticate identity) and, only after warden issues the credential, pgconn's
// own credentialed handshake in DialTarget. That is expected and correct for
// verify-before-issue — the observe never carries or receives a credential.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// sslRequestCode is the magic int32 a Postgres client sends (after the length
// prefix) to ask the server to start TLS: 1234 << 16 | 5679 (protocol 80877103).
const sslRequestCode = 80877103

// ProbeErrorKind categorizes a probe failure so the control loop can map it to a
// wire ProbeFailureCategory without pgproxy importing the dataplane proto.
type ProbeErrorKind int

// Probe failure kinds the control loop maps to wire ProbeFailureCategory values.
const (
	ProbeErrDNS ProbeErrorKind = iota
	ProbeErrConnectionRefused
	ProbeErrConnectionTimeout
	ProbeErrProtocolMismatch
	ProbeErrInsecureDowngrade
	ProbeErrMalformedIdentity
	ProbeErrIdentityTooLarge
)

// ProbeError is a categorized terminal probe failure.
type ProbeError struct {
	Kind   ProbeErrorKind
	Detail string
}

func (e *ProbeError) Error() string { return e.Detail }

// ErrNoAnchorMatch means the observed target identity satisfied none of the
// approved trust anchors — the MITM / identity-changed signal on the session path.
var ErrNoAnchorMatch = errors.New("observed target identity matches no approved anchor")

// ProbeLimits bounds the observe: per-phase timeouts and TLS chain ceilings. The
// zero value is unusable; use DefaultProbeLimits or fill from the assignment.
type ProbeLimits struct {
	DNSTimeout           time.Duration
	ConnectTimeout       time.Duration
	HandshakeTimeout     time.Duration
	TotalTimeout         time.Duration
	MaxChainCertificates int
	MaxCertificateBytes  int
}

// DefaultProbeLimits is the fixed bound used on the session-verification observe,
// where warden's per-assignment limits are not in play. Short and conservative.
func DefaultProbeLimits() ProbeLimits {
	return ProbeLimits{
		DNSTimeout:           5 * time.Second,
		ConnectTimeout:       5 * time.Second,
		HandshakeTimeout:     10 * time.Second,
		TotalTimeout:         20 * time.Second,
		MaxChainCertificates: 16,
		MaxCertificateBytes:  64 << 10,
	}
}

// Observation is what a credential-free probe saw at the target: the presented
// TLS chain (leaf first) and session metadata. No startup packet was sent.
type Observation struct {
	Chain             []*x509.Certificate
	LeafFingerprint   string // canonical "SHA256:<base64>" over the leaf DER
	ResolvedAddresses []string
	TLSVersion        string
	CipherSuite       string
	ServerName        string
	ALPN              string
	ConnectMS         int64
	HandshakeMS       int64
}

// SessionAnchor is the worker-side view of a PrepareSession trust anchor: the
// public identity constraint an operator approved. tls_leaf carries the exact leaf
// fingerprint; tls_ca carries the CA fingerprint plus the required DNS/IP name.
type SessionAnchor struct {
	ID                  string
	Kind                string // "tls_leaf" | "tls_ca"
	Fingerprint         string
	RequiredDNSNames    []string
	RequiredIPAddresses []string
}

// FingerprintDER is the canonical SHA-256 fingerprint of DER bytes, in the exact
// form warden normalizes and validates against ("SHA256:" + raw-std-base64). Used
// for both onboarding evidence and the per-session observed fingerprint so they
// compare equal to the anchor warden stored.
func FingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ObserveTarget connects to host:port, sends the pg SSLRequest, requires TLS
// acceptance ('S'), completes a TLS handshake capturing the presented chain
// WITHOUT verifying it, and stops before the pg startup packet. serverName sets
// SNI (empty falls back to host). A 'N' plaintext-only reply is a hard failure.
// It never sends or receives a credential.
func ObserveTarget(ctx context.Context, host string, port uint32, serverName string, lim ProbeLimits) (*Observation, error) {
	if lim.TotalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, lim.TotalTimeout)
		defer cancel()
	}

	// Resolve, recording the observed addresses under the DNS deadline.
	resolver := &net.Resolver{}
	dnsCtx, dnsCancel := withTimeout(ctx, lim.DNSTimeout)
	ips, err := resolver.LookupIPAddr(dnsCtx, host)
	dnsCancel()
	if err != nil {
		return nil, &ProbeError{Kind: ProbeErrDNS, Detail: "dns lookup: " + err.Error()}
	}
	if len(ips) == 0 {
		return nil, &ProbeError{Kind: ProbeErrDNS, Detail: host + " resolved to no addresses"}
	}
	resolved := make([]string, 0, len(ips))
	for _, ip := range ips {
		resolved = append(resolved, ip.String())
	}

	// Connect to the first address that answers under the connect deadline.
	connectStart := time.Now()
	conn, connErr := dialAny(ctx, ips, port, lim.ConnectTimeout)
	if connErr != nil {
		return nil, connErr
	}
	defer func() { _ = conn.Close() }()
	connectMS := time.Since(connectStart).Milliseconds()

	handshakeStart := time.Now()
	deadline := time.Now().Add(orDefault(lim.HandshakeTimeout, 10*time.Second))
	_ = conn.SetDeadline(deadline)

	// SSLRequest: int32 length (8) + int32 magic. Require a single 'S' in reply.
	if err := sendSSLRequest(conn); err != nil {
		return nil, &ProbeError{Kind: ProbeErrProtocolMismatch, Detail: "send SSLRequest: " + err.Error()}
	}
	reply := make([]byte, 1)
	if _, err := readFull(conn, reply); err != nil {
		return nil, &ProbeError{Kind: ProbeErrProtocolMismatch, Detail: "read SSLRequest reply: " + err.Error()}
	}
	switch reply[0] {
	case 'S': // server accepts TLS
	case 'N':
		return nil, &ProbeError{Kind: ProbeErrInsecureDowngrade, Detail: "target refused TLS (plaintext downgrade)"}
	default:
		return nil, &ProbeError{Kind: ProbeErrProtocolMismatch, Detail: fmt.Sprintf("unexpected SSLRequest reply %q", reply[0])}
	}

	sni := serverName
	if sni == "" {
		sni = host
	}
	var captured []*x509.Certificate
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // credential-free observe: we capture the chain; identity is enforced by MatchIdentity, not crypto/tls here
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				if lim.MaxCertificateBytes > 0 && len(c.Raw) > lim.MaxCertificateBytes {
					return &ProbeError{Kind: ProbeErrIdentityTooLarge, Detail: "certificate exceeds byte ceiling"}
				}
			}
			if lim.MaxChainCertificates > 0 && len(cs.PeerCertificates) > lim.MaxChainCertificates {
				return &ProbeError{Kind: ProbeErrIdentityTooLarge, Detail: "chain exceeds certificate ceiling"}
			}
			captured = cs.PeerCertificates
			return nil
		},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		var pe *ProbeError
		if errors.As(err, &pe) {
			return nil, pe
		}
		return nil, &ProbeError{Kind: ProbeErrProtocolMismatch, Detail: "tls handshake: " + err.Error()}
	}
	if len(captured) == 0 {
		return nil, &ProbeError{Kind: ProbeErrMalformedIdentity, Detail: "target presented no certificate"}
	}

	cs := tlsConn.ConnectionState()
	// STOP: the handshake is done and the chain captured. We never write the pg
	// startup packet — close the connection and return the observation.
	return &Observation{
		Chain:             captured,
		LeafFingerprint:   FingerprintDER(captured[0].Raw),
		ResolvedAddresses: resolved,
		TLSVersion:        tls.VersionName(cs.Version),
		CipherSuite:       tls.CipherSuiteName(cs.CipherSuite),
		ServerName:        sni,
		ALPN:              cs.NegotiatedProtocol,
		ConnectMS:         connectMS,
		HandshakeMS:       time.Since(handshakeStart).Milliseconds(),
	}, nil
}

// MatchIdentity enforces the observed target identity against the approved anchors
// before a credential is released. It returns the matched anchor id and the
// observed leaf fingerprint (to report to warden), or ErrNoAnchorMatch.
//
//   - tls_leaf: exact leaf-fingerprint equality (a pin; name/validity not re-checked,
//     matching warden's exact-equality session rule).
//   - tls_ca: the leaf must chain to a CA in caPEM (validity enforced via now), the
//     configured DNS/IP name must match the leaf, AND the anchor's CA fingerprint
//     must appear in the verified chain — binding the match to that approved CA.
func MatchIdentity(obs *Observation, caPEM string, anchors []SessionAnchor, now time.Time) (anchorID, observedFP string, err error) {
	if obs == nil || len(obs.Chain) == 0 {
		return "", "", ErrNoAnchorMatch
	}
	leafFP := obs.LeafFingerprint
	for _, a := range anchors {
		switch a.Kind {
		case "tls_leaf":
			if a.Fingerprint == leafFP {
				return a.ID, leafFP, nil
			}
		case "tls_ca":
			if matchCAAnchor(obs, caPEM, a, now) {
				return a.ID, leafFP, nil
			}
		}
	}
	return "", "", ErrNoAnchorMatch
}

// matchCAAnchor reports whether the observed leaf chains to the CA anchor a: a
// valid X.509 chain to a root in caPEM, the required DNS/IP name satisfied by the
// leaf, and the anchor's own CA fingerprint present in the verified chain.
func matchCAAnchor(obs *Observation, caPEM string, a SessionAnchor, now time.Time) bool {
	if caPEM == "" {
		return false // a CA anchor with no delivered CA material can never be validated
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return false
	}
	inter := x509.NewCertPool()
	for _, c := range obs.Chain[1:] {
		inter.AddCert(c)
	}
	leaf := obs.Chain[0]
	chains, verr := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
	})
	if verr != nil {
		return false
	}
	// Required name: a CA anchor MUST carry a name; an empty constraint never matches
	// (a bare CA must not authorize an arbitrary leaf).
	if len(a.RequiredDNSNames) == 0 && len(a.RequiredIPAddresses) == 0 {
		return false
	}
	for _, name := range a.RequiredDNSNames {
		if leaf.VerifyHostname(name) != nil {
			return false
		}
	}
	for _, ipStr := range a.RequiredIPAddresses {
		if leaf.VerifyHostname(ipStr) != nil {
			return false
		}
	}
	// The matched anchor's CA cert must actually appear in a verified chain, so the
	// match is bound to the approved CA (not merely "some CA in the delivered bundle").
	for _, chain := range chains {
		for _, c := range chain[1:] { // skip the leaf
			if FingerprintDER(c.Raw) == a.Fingerprint {
				return true
			}
		}
	}
	return false
}

// VerifiedTLSConfig builds a *tls.Config for the credentialed pgconn dial that
// re-authenticates the target against exactly the anchor already matched, so the
// second (credential-bearing) handshake proves the identical approved identity.
func VerifiedTLSConfig(host, caPEM string, anchor SessionAnchor, now func() time.Time) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // identity verified in VerifyConnection against the already-matched anchor
		VerifyConnection: func(cs tls.ConnectionState) error {
			obs := &Observation{Chain: cs.PeerCertificates}
			if len(obs.Chain) > 0 {
				obs.LeafFingerprint = FingerprintDER(obs.Chain[0].Raw)
			}
			if _, _, err := MatchIdentity(obs, caPEM, []SessionAnchor{anchor}, now()); err != nil {
				return fmt.Errorf("credentialed handshake identity: %w", err)
			}
			return nil
		},
	}
}

func sendSSLRequest(conn net.Conn) error {
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[0:4], 8)
	binary.BigEndian.PutUint32(buf[4:8], sslRequestCode)
	_, err := conn.Write(buf[:])
	return err
}

func dialAny(ctx context.Context, ips []net.IPAddr, port uint32, perAddr time.Duration) (net.Conn, *ProbeError) {
	var last *ProbeError
	d := net.Dialer{}
	for _, ip := range ips {
		addrCtx, cancel := withTimeout(ctx, perAddr)
		conn, err := d.DialContext(addrCtx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		cancel()
		if err == nil {
			return conn, nil
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			last = &ProbeError{Kind: ProbeErrConnectionTimeout, Detail: "connect timeout: " + err.Error()}
		} else {
			last = &ProbeError{Kind: ProbeErrConnectionRefused, Detail: "connect: " + err.Error()}
		}
	}
	if last == nil {
		last = &ProbeError{Kind: ProbeErrConnectionRefused, Detail: "no address answered"}
	}
	return nil, last
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// readFull reads len(p) bytes or returns an error (net.Conn has no io.ReadFull-safe
// short-read guarantee on its own).
func readFull(conn net.Conn, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := conn.Read(p[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
