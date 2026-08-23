// Package recording provides object-store access for session recordings. It
// issues short-lived presigned download URLs for recorded objects and supports
// server-side streaming of objects directly to HTTP clients.
package recording

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Presigner issues short-lived presigned GET URLs for recording objects and
// can also stream object bodies directly (for server-proxy use).
type S3Presigner struct {
	raw    *s3.Client        // for GetObject (direct streaming)
	client *s3.PresignClient // for PresignGetObject (URL generation)
	bucket string
}

// NewS3Presigner builds a presigner against an S3-compatible endpoint. A custom
// endpoint + path-style addressing supports self-hosted stores; credentials come
// from the standard AWS SDK chain (env, IRSA, ...).
func NewS3Presigner(ctx context.Context, bucket, endpoint, region string) (*S3Presigner, error) {
	if bucket == "" {
		return nil, errors.New("recording bucket not configured")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	raw := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = &endpoint
			o.UsePathStyle = true
		}
	})
	return &S3Presigner{raw: raw, client: s3.NewPresignClient(raw), bucket: bucket}, nil
}

// PresignGet returns a presigned GET URL for objectKey valid for ttl.
func (p *S3Presigner) PresignGet(ctx context.Context, objectKey string, ttl time.Duration) (string, time.Time, error) {
	req, err := p.client.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &p.bucket, Key: &objectKey,
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("presign get: %w", err)
	}
	return req.URL, time.Now().Add(ttl), nil
}

// GetObject streams the object body for key from the bucket. The caller is
// responsible for closing the returned ReadCloser.
func (p *S3Presigner) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := p.raw.GetObject(ctx, &s3.GetObjectInput{Bucket: &p.bucket, Key: &key})
	if err != nil {
		return nil, fmt.Errorf("get object: %w", err)
	}
	return out.Body, nil
}

// Put writes body to key in the bucket. It exists so warden can anchor the audit
// hash-chain tip to the object store (audit.AnchorStore); recordings themselves
// are uploaded by the worker, so this is the only write path warden needs.
func (p *S3Presigner) Put(ctx context.Context, key string, body []byte) error {
	_, err := p.raw.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &p.bucket,
		Key:         &key,
		Body:        bytes.NewReader(body),
		ContentType: awsString("application/json"),
	})
	if err != nil {
		return fmt.Errorf("put object: %w", err)
	}
	return nil
}

func awsString(s string) *string { return &s }
