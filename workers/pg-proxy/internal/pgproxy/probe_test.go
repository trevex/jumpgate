package pgproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// fakePG is a minimal TLS-capable Postgres stand-in: it answers the SSLRequest
// with 'S' (or 'N' when downgrade) and, on 'S', completes a TLS handshake
// presenting cert. It records whether ANY application byte arrived after the
// handshake — the probe must STOP before the pg startup packet, so a correct
// observe leaves postStartupSeen false.
type fakePG struct {
	ln            net.Listener
	cert          tls.Certificate
	downgrade     bool
	mu            sync.Mutex
	postStartup   bool
	handshakeDone bool
}

func startFakePG(t *testing.T, cert tls.Certificate, downgrade bool) *fakePG {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePG{ln: ln, cert: cert, downgrade: downgrade}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakePG) addr() (string, uint32) {
	a := f.ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", uint32(a.Port) //nolint:gosec // ephemeral test port fits uint32
}

func (f *fakePG) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakePG) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hdr [8]byte
	if _, err := readFull(conn, hdr[:]); err != nil {
		return
	}
	if binary.BigEndian.Uint32(hdr[4:8]) != sslRequestCode {
		return
	}
	if f.downgrade {
		_, _ = conn.Write([]byte{'N'})
		return
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	f.mu.Lock()
	f.handshakeDone = true
	f.mu.Unlock()
	// After the handshake a real client would send the pg startup packet. The probe
	// must not — read with a short deadline and record any byte that arrives.
	_ = tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if n, _ := tlsConn.Read(buf); n > 0 {
		f.mu.Lock()
		f.postStartup = true
		f.mu.Unlock()
	}
}

func (f *fakePG) sawStartup() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.postStartup
}

// --- certificate fixtures -------------------------------------------------

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newCA(t *testing.T) ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return ca{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

type leafOpts struct {
	dnsNames  []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
}

// signLeaf issues a leaf from ca (or self-signs when ca is nil) and returns the
// serving tls.Certificate plus the parsed leaf.
func signLeaf(t *testing.T, issuer *ca, o leafOpts) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb, na := o.notBefore, o.notAfter
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	if na.IsZero() {
		na = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     o.dnsNames,
		IPAddresses:  o.ips,
	}
	parent, parentKey := tmpl, key
	if issuer != nil {
		parent, parentKey = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	serving := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	if issuer != nil {
		serving.Certificate = append(serving.Certificate, issuer.cert.Raw)
	}
	_ = keyDER
	return serving, leaf
}

func testLimits() ProbeLimits {
	l := DefaultProbeLimits()
	l.DNSTimeout = 2 * time.Second
	l.ConnectTimeout = 2 * time.Second
	l.HandshakeTimeout = 3 * time.Second
	l.TotalTimeout = 6 * time.Second
	return l
}

// --- tests ----------------------------------------------------------------

func TestObserveStopsBeforeStartup(t *testing.T) {
	c := newCA(t)
	serving, leaf := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}})
	f := startFakePG(t, serving, false)
	host, port := f.addr()

	obs, err := ObserveTarget(context.Background(), host, port, "db.test", testLimits())
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if obs.LeafFingerprint != FingerprintDER(leaf.Raw) {
		t.Fatalf("leaf fingerprint mismatch")
	}
	// The crux: no pg startup packet may follow the observe.
	time.Sleep(200 * time.Millisecond)
	if f.sawStartup() {
		t.Fatal("probe sent a pg startup packet after the TLS handshake — it must STOP before startup")
	}
}

func TestObserveRejectsPlaintextDowngrade(t *testing.T) {
	c := newCA(t)
	serving, _ := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}})
	f := startFakePG(t, serving, true) // answers 'N'
	host, port := f.addr()

	_, err := ObserveTarget(context.Background(), host, port, "db.test", testLimits())
	var pe *ProbeError
	if err == nil || !asProbeErr(err, &pe) || pe.Kind != ProbeErrInsecureDowngrade {
		t.Fatalf("want insecure-downgrade failure, got %v", err)
	}
}

func TestObserveHonorsCertByteCeiling(t *testing.T) {
	c := newCA(t)
	serving, _ := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}})
	f := startFakePG(t, serving, false)
	host, port := f.addr()

	lim := testLimits()
	lim.MaxCertificateBytes = 10 // any real cert exceeds this
	_, err := ObserveTarget(context.Background(), host, port, "db.test", lim)
	var pe *ProbeError
	if err == nil || !asProbeErr(err, &pe) || pe.Kind != ProbeErrIdentityTooLarge {
		t.Fatalf("want identity-too-large failure, got %v", err)
	}
}

func TestMatchTLSCASuccess(t *testing.T) {
	c := newCA(t)
	_, leaf := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}})
	obs := &Observation{Chain: []*x509.Certificate{leaf, c.cert}, LeafFingerprint: FingerprintDER(leaf.Raw)}
	anchor := SessionAnchor{ID: "a1", Kind: "tls_ca", Fingerprint: FingerprintDER(c.cert.Raw), RequiredDNSNames: []string{"db.test"}}

	id, fp, err := MatchIdentity(obs, c.pem, []SessionAnchor{anchor}, time.Now())
	if err != nil || id != "a1" || fp != FingerprintDER(leaf.Raw) {
		t.Fatalf("want match a1, got id=%q fp=%q err=%v", id, fp, err)
	}
}

func TestMatchTLSCARejectsWrongName(t *testing.T) {
	c := newCA(t)
	_, leaf := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}})
	obs := &Observation{Chain: []*x509.Certificate{leaf, c.cert}, LeafFingerprint: FingerprintDER(leaf.Raw)}
	anchor := SessionAnchor{ID: "a1", Kind: "tls_ca", Fingerprint: FingerprintDER(c.cert.Raw), RequiredDNSNames: []string{"evil.test"}}

	if _, _, err := MatchIdentity(obs, c.pem, []SessionAnchor{anchor}, time.Now()); !errors.Is(err, ErrNoAnchorMatch) {
		t.Fatalf("valid CA but wrong name must reject, got %v", err)
	}
}

func TestMatchTLSCARejectsExpired(t *testing.T) {
	c := newCA(t)
	_, leaf := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}, notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-24 * time.Hour)})
	obs := &Observation{Chain: []*x509.Certificate{leaf, c.cert}, LeafFingerprint: FingerprintDER(leaf.Raw)}
	anchor := SessionAnchor{ID: "a1", Kind: "tls_ca", Fingerprint: FingerprintDER(c.cert.Raw), RequiredDNSNames: []string{"db.test"}}

	if _, _, err := MatchIdentity(obs, c.pem, []SessionAnchor{anchor}, time.Now()); !errors.Is(err, ErrNoAnchorMatch) {
		t.Fatalf("expired leaf must reject, got %v", err)
	}
}

func TestMatchTLSCARejectsNotYetValid(t *testing.T) {
	c := newCA(t)
	_, leaf := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}, notBefore: time.Now().Add(24 * time.Hour), notAfter: time.Now().Add(48 * time.Hour)})
	obs := &Observation{Chain: []*x509.Certificate{leaf, c.cert}, LeafFingerprint: FingerprintDER(leaf.Raw)}
	anchor := SessionAnchor{ID: "a1", Kind: "tls_ca", Fingerprint: FingerprintDER(c.cert.Raw), RequiredDNSNames: []string{"db.test"}}

	if _, _, err := MatchIdentity(obs, c.pem, []SessionAnchor{anchor}, time.Now()); !errors.Is(err, ErrNoAnchorMatch) {
		t.Fatalf("not-yet-valid leaf must reject, got %v", err)
	}
}

func TestMatchTLSCARejectsWrongCA(t *testing.T) {
	c := newCA(t)
	other := newCA(t)
	_, leaf := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}})
	obs := &Observation{Chain: []*x509.Certificate{leaf, c.cert}, LeafFingerprint: FingerprintDER(leaf.Raw)}
	// Anchor names the OTHER CA; the leaf does not chain to it.
	anchor := SessionAnchor{ID: "a1", Kind: "tls_ca", Fingerprint: FingerprintDER(other.cert.Raw), RequiredDNSNames: []string{"db.test"}}

	if _, _, err := MatchIdentity(obs, other.pem, []SessionAnchor{anchor}, time.Now()); !errors.Is(err, ErrNoAnchorMatch) {
		t.Fatalf("leaf not chaining to the anchored CA must reject, got %v", err)
	}
}

func TestMatchSelfSignedLeafPin(t *testing.T) {
	_, leaf := signLeaf(t, nil, leafOpts{}) // self-signed, no SAN
	obs := &Observation{Chain: []*x509.Certificate{leaf}, LeafFingerprint: FingerprintDER(leaf.Raw)}
	anchor := SessionAnchor{ID: "pin", Kind: "tls_leaf", Fingerprint: FingerprintDER(leaf.Raw)}

	id, fp, err := MatchIdentity(obs, "", []SessionAnchor{anchor}, time.Now())
	if err != nil || id != "pin" || fp != FingerprintDER(leaf.Raw) {
		t.Fatalf("self-signed leaf pin must match, got id=%q err=%v", id, err)
	}
}

func TestMatchLeafPinRejectsDifferentCert(t *testing.T) {
	_, leaf := signLeaf(t, nil, leafOpts{})
	_, other := signLeaf(t, nil, leafOpts{})
	obs := &Observation{Chain: []*x509.Certificate{leaf}, LeafFingerprint: FingerprintDER(leaf.Raw)}
	anchor := SessionAnchor{ID: "pin", Kind: "tls_leaf", Fingerprint: FingerprintDER(other.Raw)}

	if _, _, err := MatchIdentity(obs, "", []SessionAnchor{anchor}, time.Now()); !errors.Is(err, ErrNoAnchorMatch) {
		t.Fatalf("a different cert must not satisfy a leaf pin, got %v", err)
	}
}

func TestMatchMultipleAnchors(t *testing.T) {
	c := newCA(t)
	_, leaf := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}})
	obs := &Observation{Chain: []*x509.Certificate{leaf, c.cert}, LeafFingerprint: FingerprintDER(leaf.Raw)}
	anchors := []SessionAnchor{
		{ID: "stale", Kind: "tls_leaf", Fingerprint: "SHA256:AAAA"},
		{ID: "ca", Kind: "tls_ca", Fingerprint: FingerprintDER(c.cert.Raw), RequiredDNSNames: []string{"db.test"}},
	}
	id, _, err := MatchIdentity(obs, c.pem, anchors, time.Now())
	if err != nil || id != "ca" {
		t.Fatalf("second (CA) anchor should match, got id=%q err=%v", id, err)
	}
}

func TestMatchCAAnchorWithoutNameRejected(t *testing.T) {
	c := newCA(t)
	_, leaf := signLeaf(t, &c, leafOpts{dnsNames: []string{"db.test"}})
	obs := &Observation{Chain: []*x509.Certificate{leaf, c.cert}, LeafFingerprint: FingerprintDER(leaf.Raw)}
	anchor := SessionAnchor{ID: "a1", Kind: "tls_ca", Fingerprint: FingerprintDER(c.cert.Raw)} // no required name

	if _, _, err := MatchIdentity(obs, c.pem, []SessionAnchor{anchor}, time.Now()); !errors.Is(err, ErrNoAnchorMatch) {
		t.Fatalf("a CA anchor with no name constraint must not authorize an arbitrary leaf, got %v", err)
	}
}

func asProbeErr(err error, target **ProbeError) bool {
	return errors.As(err, target)
}
