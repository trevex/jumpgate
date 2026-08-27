package recording

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewS3PresignerEmptyBucket(t *testing.T) {
	if _, err := NewS3Presigner(context.Background(), "", "", "", "us-east-1"); err == nil {
		t.Fatal("expected error for empty bucket, got nil")
	}
}

func TestPresignGetProducesURL(t *testing.T) {
	// Static creds so LoadDefaultConfig does not consult the ambient chain.
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	ctx := context.Background()
	const (
		bucket = "recordings"
		key    = "recordings/ssh/x.cast"
		ttl    = time.Minute
	)
	p, err := NewS3Presigner(ctx, bucket, "http://localhost:9000", "", "us-east-1")
	if err != nil {
		t.Fatalf("NewS3Presigner: %v", err)
	}

	before := time.Now()
	url, exp, err := p.PresignGet(ctx, key, ttl)
	if err != nil {
		t.Fatalf("PresignGet: %v", err)
	}
	if url == "" {
		t.Fatal("expected non-empty presigned URL")
	}
	if !strings.Contains(url, bucket) {
		t.Errorf("URL %q does not contain bucket %q", url, bucket)
	}
	// The object key appears in the path (URL-escaped slashes may remain literal).
	if !strings.Contains(url, "ssh/x.cast") {
		t.Errorf("URL %q does not contain key %q", url, key)
	}

	wantMin := before.Add(ttl)
	wantMax := time.Now().Add(ttl)
	if exp.Before(wantMin.Add(-time.Second)) || exp.After(wantMax.Add(time.Second)) {
		t.Errorf("expiry %v not within [%v, %v]", exp, wantMin, wantMax)
	}
}

// TestPresignGetUsesPublicEndpoint guards the split that fixes the kind cast-proxy
// 404: presigned download URLs must be signed against the client-reachable public
// endpoint, while server-side GetObject targets the (separate) warden-reachable
// endpoint. A single endpoint cannot serve both when warden runs in-cluster and the
// downloader is off-cluster.
func TestPresignGetUsesPublicEndpoint(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	ctx := context.Background()
	const (
		internalEndpoint = "http://jumpgate-silo.internal:9000" // in-cluster only
		publicEndpoint   = "http://localhost:30900"             // NodePort, host-reachable
	)
	p, err := NewS3Presigner(ctx, "recordings", internalEndpoint, publicEndpoint, "us-east-1")
	if err != nil {
		t.Fatalf("NewS3Presigner: %v", err)
	}

	url, _, err := p.PresignGet(ctx, "recordings/ssh/x.cast", time.Minute)
	if err != nil {
		t.Fatalf("PresignGet: %v", err)
	}
	if !strings.Contains(url, "localhost:30900") {
		t.Errorf("presigned URL %q does not use the public endpoint host localhost:30900", url)
	}
	if strings.Contains(url, "jumpgate-silo.internal") {
		t.Errorf("presigned URL %q leaked the internal endpoint host", url)
	}
}
