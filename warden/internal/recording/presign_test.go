package recording

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewS3PresignerEmptyBucket(t *testing.T) {
	if _, err := NewS3Presigner(context.Background(), "", "", "us-east-1"); err == nil {
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
	p, err := NewS3Presigner(ctx, bucket, "http://localhost:9000", "us-east-1")
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
