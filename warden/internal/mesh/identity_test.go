package mesh

import (
	"context"
	"net/url"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestParseIdentity(t *testing.T) {
	id, err := ParseIdentity(mustURL(t, "spiffe://jumpgate/worker/w-123"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Role != "worker" || id.ID != "w-123" {
		t.Fatalf("got %+v", id)
	}
	// gateway role has no id segment? gateway uses spiffe://jumpgate/gateway/<name>.
	if _, err := ParseIdentity(mustURL(t, "spiffe://other/worker/x")); err == nil {
		t.Fatal("wrong trust domain must fail")
	}
	if _, err := ParseIdentity(mustURL(t, "spiffe://jumpgate/worker")); err == nil {
		t.Fatal("missing id must fail")
	}
	if _, err := ParseIdentity(mustURL(t, "https://jumpgate/worker/x")); err == nil {
		t.Fatal("non-spiffe scheme must fail")
	}
}

func TestContextRoundTrip(t *testing.T) {
	ctx := WithIdentity(context.Background(), Identity{Role: "gateway", ID: "gw"})
	got, ok := IdentityFromContext(ctx)
	if !ok || got.Role != "gateway" || got.ID != "gw" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if _, ok := IdentityFromContext(context.Background()); ok {
		t.Fatal("empty ctx must have no identity")
	}
}

func TestSpiffeIDString(t *testing.T) {
	if got := (Identity{Role: "worker", ID: "w1"}).SpiffeID(); got != "spiffe://jumpgate/worker/w1" {
		t.Fatalf("SpiffeID() = %s", got)
	}
}
