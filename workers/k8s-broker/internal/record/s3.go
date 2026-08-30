package record

import (
	"bytes"
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3Uploader writes recordings to an S3-compatible store.
type s3Uploader struct {
	client *s3.Client
	bucket string
}

// NewS3Uploader builds an Uploader, or returns a nil Uploader (recording disabled)
// when bucket is empty. Credentials come from the standard AWS SDK chain (env,
// IRSA, ...). The return type is the Uploader interface so an empty bucket yields a
// genuine nil interface (not a typed-nil), which callers can compare against nil.
func NewS3Uploader(ctx context.Context, bucket, endpoint, region string) (Uploader, error) {
	if bucket == "" {
		return nil, nil
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
	return &s3Uploader{client: client, bucket: bucket}, nil
}

func (u *s3Uploader) Put(ctx context.Context, key string, body []byte) error {
	ct := "application/x-ndjson"
	if _, err := u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &u.bucket,
		Key:         &key,
		Body:        bytes.NewReader(body),
		ContentType: &ct,
	}); err != nil {
		return fmt.Errorf("put object: %w", err)
	}
	return nil
}
