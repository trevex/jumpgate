package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

// dexIssuerHost is the issuer host:port for Dex (test/env/testworkload/dex.yaml): the single
// string that must match the ID token `iss`, be reachable by warden in-cluster, and be
// reachable by whoever drives the browser leg. We use `dex.localhost` so a real browser
// resolves it to loopback natively (→ the NodePort) while warden resolves it in-cluster via a
// CoreDNS rewrite (see the Makefile kind-up target). Dex derives every endpoint in its
// discovery document (authorization_endpoint, token_endpoint, the /callback it bounces
// through) from this string, so the browser leg hits Dex at this *exact* host:port.
const dexIssuerHost = "dex.localhost:5556"

// dexHostAddr is the localhost address cluster.yaml maps to Dex's NodePort, i.e. how this
// test process (running on the host, outside the cluster) reaches the very same Dex
// instance warden talks to in-cluster.
const dexHostAddr = "127.0.0.1:5556"

// oidcSessionCookie mirrors warden/internal/auth.SessionCookie. The e2e module doesn't
// import warden's Go packages (it drives everything black-box through the CLI/HTTP), so
// the name is duplicated here rather than pulled in as a dependency for one constant.
const oidcSessionCookie = "jumpgate_session"

// dex's mockCallback connector (connector/mock/connectortest.go NewCallbackConnector,
// registered as connector type "mockCallback" in dex's own binary — see
// server/connector.go — specifically for tests like this one) always asserts one fixed,
// hardcoded identity: no configuration, no user interaction. Verified live against a real
// Dex v2.45.1 instance while authoring this test (`kubectl exec ... curl .../token` and
// decoding the id_token) to land on exactly these values.
const (
	oidcUserEmail = "kilgore@kilgore.trout"
	oidcGroupKey  = "authors"
)

// oidcHTTPClient returns an http.Client that plays "browser" for the OIDC auth-code flow:
// it follows redirects and keeps cookies (both warden's state/session cookies and dex's
// own), exactly like a real browser tab would.
//
// The one wrinkle: this test process runs on the host but isn't a browser, so it gets neither
// the browser's native *.localhost→loopback resolution nor warden's in-cluster CoreDNS
// rewrite. Rather than depend on either, the transport below special-cases dials to
// dexIssuerHost and redirects them to dexHostAddr (the NodePort) — the exact same trick as
// `curl --resolve`. Every hop in the login flow that targets dex (the initial redirect off of
// /auth/oidc/login, and dex's own internal bounce through /callback) goes through this one
// substitution transparently.
func oidcHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == dexIssuerHost {
				addr = dexHostAddr
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Jar: jar, Transport: transport, Timeout: 30 * time.Second}
}

// performOIDCLogin drives the full browser leg of the auth-code flow against wardenBase
// (e.g. "http://localhost:8080") — GET /auth/oidc/login, follow every redirect through dex
// and back to warden's callback — and returns the resulting jumpgate_session token. That
// token is the same opaque bearer-token space the CLI's own `login` uses (see
// warden/internal/auth/session.go ExtractToken, which accepts it from either the
// Authorization header or this cookie), so the caller can feed it straight into the CLI via
// --token to verify what the JIT-provisioned user can see, without teaching the CLI
// anything about cookies or browsers.
func performOIDCLogin(t *testing.T, wardenBase string) string {
	t.Helper()
	client := oidcHTTPClient(t)

	resp, err := client.Get(wardenBase + "/auth/oidc/login")
	if err != nil {
		t.Fatalf("oidc login flow: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if strings.Contains(resp.Request.URL.String(), "error=oidc") {
		t.Fatalf("oidc login bounced back to the login page with an error (landed on %s)", resp.Request.URL)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("oidc login flow ended with status %d at %s (want 200 on warden's post-login page)", resp.StatusCode, resp.Request.URL)
	}

	wardenURLParsed, err := resp.Request.URL.Parse(wardenBase)
	if err != nil {
		t.Fatalf("parse warden base: %v", err)
	}
	for _, c := range client.Jar.Cookies(wardenURLParsed) {
		if c.Name == oidcSessionCookie {
			return c.Value
		}
	}
	t.Fatalf("no %s cookie after oidc login flow (landed on %s)", oidcSessionCookie, resp.Request.URL)
	return ""
}

// cliLoopbackRedirect is a placeholder loopback redirect_uri for performOIDCLoginCLI.
// In the real CLI (cli/cmd/login.go runLoginSSO) this is `http://127.0.0.1:<port>`
// for a listener it actually opens; here nothing ever binds this port — the test
// intercepts the redirect to it (see performOIDCLoginCLI) before any dial would
// happen, so no listener is needed.
const cliLoopbackRedirect = "http://127.0.0.1:45999/callback"

// performOIDCLoginCLI drives warden's CLI-loopback OIDC endpoints
// (GET /auth/oidc/cli/login, POST /auth/oidc/cli/exchange — warden/internal/httpapi/oidc_cli.go)
// end to end against a real Dex, proving out the backend `jumpgate login --sso`
// (cli/cmd/login.go runLoginSSO) relies on — without a real browser or a real loopback
// listener. It plays "browser" exactly like performOIDCLogin (same Dex dial rewrite +
// cookie jar), except its CheckRedirect stops just short of following the final
// redirect to cliLoopbackRedirect (mirroring runLoginSSO's own loopback server, which
// would receive that exact request) and reads the one-time `code` off that redirect's
// Location instead. It then exchanges that code for a bearer the same way
// exchangeCLICode does, and returns the bearer.
func performOIDCLoginCLI(t *testing.T, wardenBase string) string {
	t.Helper()
	client := oidcHTTPClient(t)
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Hostname() == "127.0.0.1" {
			return http.ErrUseLastResponse
		}
		return nil
	}

	resp, err := client.Get(wardenBase + "/auth/oidc/cli/login?redirect_uri=" + url.QueryEscape(cliLoopbackRedirect))
	if err != nil {
		t.Fatalf("cli oidc login flow: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("cli oidc login flow ended with status %d at %s (want 302 to the loopback redirect_uri)", resp.StatusCode, resp.Request.URL)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("parse final redirect Location: %v", err)
	}
	if !strings.HasPrefix(loc.String(), cliLoopbackRedirect) {
		t.Fatalf("final redirect = %q, want prefix %q", loc.String(), cliLoopbackRedirect)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in final redirect %s (error=%s)", loc.String(), loc.Query().Get("error"))
	}

	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		t.Fatalf("marshal exchange body: %v", err)
	}
	exResp, err := client.Post(wardenBase+"/auth/oidc/cli/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("cli exchange: %v", err)
	}
	defer func() { _ = exResp.Body.Close() }()
	if exResp.StatusCode != http.StatusOK {
		t.Fatalf("cli exchange status = %d, want 200", exResp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(exResp.Body).Decode(&out); err != nil {
		t.Fatalf("decode exchange response: %v", err)
	}
	if out.Token == "" {
		t.Fatal("empty token from cli exchange")
	}
	return out.Token
}

// TestOIDCLogin drives a real browser-shaped OIDC auth-code login against the Dex test IdP
// end to end and proves the three things B9 cares about: the login JIT-provisions a local
// user, syncs the IdP's asserted group into an origin='oidc' membership on the
// external_key-matched jumpgate group, and that membership's role binding is what the
// resulting session actually sees.
func TestOIDCLogin(t *testing.T) {
	if shared == nil {
		t.Skip("no live cluster (set JUMPGATE_E2E=1)")
	}
	e := shared
	e.reset(t)

	folder := e.name("oidc-demo")
	groupName := e.name("oidc-ops")

	e.exportMeshCA(t)
	e.login(t, "admin", adminEmail, adminPass)

	e.asActor(t, "admin", "folders", "create", folder)
	assetOut := e.asActor(t, "admin", "assets", "ssh", "create", e.name("oidc-box"),
		"--folder", folder, "--target", "ssh-target.default.svc.cluster.local:22", "--login", "demo",
		"-o", "json")
	assetPath := jsonField(assetOut, "path")
	if assetPath == "" {
		t.Fatalf("no asset path in create output:\n%s", assetOut)
	}

	groupOut := e.asActor(t, "admin", "groups", "create", groupName, "--folder", folder, "-o", "json")
	groupID := jsonID(groupOut)
	if groupID == "" {
		t.Fatalf("no group id:\n%s", groupOut)
	}
	// Map the group to Dex's "authors" groups claim via the SetGroupExternalKey RPC
	// surface (cli/cmd/groups.go), so the JIT login below syncs an origin='oidc'
	// membership onto it.
	e.asActor(t, "admin", "groups", "set-external-key", groupID, oidcGroupKey)

	e.asActor(t, "admin", "roles", "create", "oidc-viewer", "--folder", folder, "--capability", "ssh:login:demo")
	e.asActor(t, "admin", "bindings", "create",
		"--role", "oidc-viewer."+folder, "--group", groupID, "--asset", assetPath)

	token := performOIDCLogin(t, e.wardenURL)

	t.Run("jit_provisions_user", func(t *testing.T) {
		// dex's mockCallback connector always asserts the same fixed identity, so the
		// login above should have created exactly this local user on first login.
		usersOut := e.asActor(t, "admin", "users", "list", "-o", "json")
		if !strings.Contains(usersOut, oidcUserEmail) {
			t.Fatalf("JIT-provisioned user %s not found after oidc login:\n%s", oidcUserEmail, usersOut)
		}
	})

	t.Run("syncs_group_membership_as_oidc_origin", func(t *testing.T) {
		origin := strings.TrimSpace(e.execSQL(t, fmt.Sprintf(
			`SELECT origin FROM group_memberships gm JOIN users u ON u.id = gm.member_user_id WHERE gm.group_id = '%s' AND u.email = '%s';`,
			groupID, oidcUserEmail)))
		if origin != "oidc" {
			t.Fatalf("group membership origin = %q, want %q", origin, "oidc")
		}
	})

	t.Run("user_sees_the_group_granted_access", func(t *testing.T) {
		// The synced membership carries the role binding's ssh:login:demo on assetPath, so
		// the JIT user's own catalog browse should include it. --token reuses the exact
		// bearer-token space the OIDC session cookie was minted from (see
		// performOIDCLogin) directly against the CLI, sidestepping the fact that this
		// "actor" never ran `jumpgate login` and has no stored context.
		out := run(t, []string{"XDG_CONFIG_HOME=" + e.configDir}, e.jgBin,
			"--warden-addr", e.wardenURL, "--token", token,
			"assets", "list", "--cascade", "-o", "json")
		if !strings.Contains(out, assetPath) {
			t.Fatalf("oidc-provisioned user should see the group-granted asset %s:\n%s", assetPath, out)
		}
	})

	t.Run("cli_loopback_login_matches_browser_flow", func(t *testing.T) {
		// Proves out jumpgate login --sso's backend (warden's /auth/oidc/cli/login +
		// /auth/oidc/cli/exchange) end to end against the same Dex identity and the
		// same fixtures the browser subtests above already exercised, without a real
		// browser or a real loopback listener — see performOIDCLoginCLI.
		cliToken := performOIDCLoginCLI(t, e.wardenURL)

		out := run(t, []string{"XDG_CONFIG_HOME=" + e.configDir}, e.jgBin,
			"--warden-addr", e.wardenURL, "--token", cliToken,
			"assets", "list", "--cascade", "-o", "json")
		if !strings.Contains(out, assetPath) {
			t.Fatalf("cli-oidc-provisioned user should see the group-granted asset %s:\n%s", assetPath, out)
		}
	})

	// Revocation-on-claim-loss (a group leaving the ID token's groups claim tears down the
	// origin='oidc' membership on the next login) is exercised at the unit level already —
	// see warden/internal/oidc/provision_test.go's SyncGroups coverage. Reproducing it here
	// would need a second Dex identity with a different groups claim for the *same*
	// (issuer, subject); dex's mockCallback connector is fixed/unconfigurable per identity
	// (that's exactly what makes the flow above scriptable without a real browser — see
	// dex.yaml), so driving that from this black-box suite would mean adding a second,
	// separately-configured mock connector (or switching to the password-DB + HTML-form
	// flow) purely to flip one claim. Left as a follow-up rather than done here.
}
