// Package recording provides object-store access for session recordings. It
// issues short-lived presigned download URLs for recorded objects.
package recording

import (
	"context"
	"errors"
	"fmt"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Presigner issues short-lived presigned GET URLs for recording objects.
type S3Presigner struct {
	client *s3.PresignClient
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
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = &endpoint
			o.UsePathStyle = true
		}
	})
	return &S3Presigner{client: s3.NewPresignClient(client), bucket: bucket}, nil
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
