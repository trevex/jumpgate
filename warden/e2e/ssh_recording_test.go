//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	gossh "golang.org/x/crypto/ssh"

	clicmd "github.com/trevex/jumpgate/cli/cmd"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// recordingBucket is the object-store bucket the worker uploads recordings to and
// warden presigns downloads from.
const recordingBucket = "jumpgate-recordings"

// exemptUserEmail is a second user seeded with ssh:login:deploy AND
// ssh:record:exempt, used to prove an exempt session is NOT recorded.
const exemptUserEmail = "exempt@e2e.test"

// siloInfo describes a running Silo (S3-compatible) object store.
type siloInfo struct {
	endpoint  string
	bucket    string
	accessKey string
	secretKey string
}

// startSilo launches a real Silo (MinIO-protocol) server as a subprocess, waits
// for it to accept connections, and creates the recording bucket via the AWS SDK.
// It returns the store's endpoint/bucket/credentials for wiring into warden and
// the worker. The process is killed on test cleanup.
func startSilo(t *testing.T) siloInfo {
	t.Helper()

	addr := reservePort(t)
	consoleAddr := reservePort(t)
	dataDir := t.TempDir()
	endpoint := "http://" + addr
	const accessKey = "minioadmin"
	const secretKey = "minioadmin-test-secret"

	// silo server <datadir> --address :P --console-address :Pc, credentials via the
	// MinIO env names (silo speaks the MinIO protocol).
	cmd := exec.Command("silo", "server", dataDir, "--address", addr, "--console-address", consoleAddr) // #nosec G204 -- fixed tool + reserved loopback ports
	cmd.Env = append(os.Environ(),
		"MINIO_ROOT_USER="+accessKey,
		"MINIO_ROOT_PASSWORD="+secretKey,
	)
	startSubprocess(t, "silo", cmd)
	waitTCP(t, "silo", addr)

	info := siloInfo{endpoint: endpoint, bucket: recordingBucket, accessKey: accessKey, secretKey: secretKey}

	// Create the recording bucket. Silo's HTTP surface may come up a beat after the
	// TCP port accepts, so retry the create briefly.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := s3Client(t, info)
	var lastErr error
	for {
		_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &info.bucket})
		if err == nil {
			return info
		}
		lastErr = err
		if ctx.Err() != nil {
			t.Fatalf("create recording bucket: %v", lastErr)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// s3Client builds an AWS SDK S3 client for the given Silo store: path-style
// addressing, a custom base endpoint, static credentials, and region us-east-1.
func s3Client(t *testing.T, info siloInfo) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(info.accessKey, info.secretKey, "")),
	)
	if err != nil {
		t.Fatalf("aws config: %v", err)
	}
	endpoint := info.endpoint
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = &endpoint
		o.UsePathStyle = true
	})
}

// startSubprocess launches cmd, streams its output into a buffer dumped on
// failure, and kills it on cleanup. It mirrors startProcess but takes a
// pre-built *exec.Cmd so callers can set positional args + env.
func startSubprocess(t *testing.T, name string, cmd *exec.Cmd) {
	t.Helper()
	var mu sync.Mutex
	var buf strings.Builder
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("%s pipe: %v", name, err)
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	_ = pw.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := pr.Read(b)
			if n > 0 {
				mu.Lock()
				buf.Write(b[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			mu.Lock()
			logs := buf.String()
			mu.Unlock()
			t.Logf("=== %s logs ===\n%s", name, logs)
		}
	})
}

// recordingRow is a session_recordings row projection.
type recordingRow struct {
	sessionID string
	status    string
	objectKey string
	sha256    string
	sizeBytes int64
}

// latestRecording returns the most recent session_recordings row, or ok=false if
// the table is empty.
func latestRecording(t *testing.T, pool *pgxpool.Pool) (recordingRow, bool) {
	t.Helper()
	var r recordingRow
	err := pool.QueryRow(context.Background(),
		`SELECT session_id::text, status, object_key, sha256, size_bytes
		   FROM session_recordings ORDER BY created_at DESC LIMIT 1`).
		Scan(&r.sessionID, &r.status, &r.objectKey, &r.sha256, &r.sizeBytes)
	if err != nil {
		return recordingRow{}, false
	}
	return r, true
}

// recordingCount returns the number of session_recordings rows.
func recordingCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM session_recordings`).Scan(&n); err != nil {
		t.Fatalf("count session_recordings: %v", err)
	}
	return n
}

// assertRecordedSession waits for the happy-path exec's required recording to be
// uploaded and reported, then downloads the object from Silo and verifies it is a
// well-formed asciicast v2 stream whose bytes exactly match the stored digest.
func assertRecordedSession(ctx context.Context, t *testing.T, pool *pgxpool.Pool, silo siloInfo) {
	t.Helper()

	// Poll for a completed recording row (the worker uploads + reports after the
	// session ends; warden persists it out of band).
	var rec recordingRow
	deadline := time.Now().Add(20 * time.Second)
	for {
		if r, ok := latestRecording(t, pool); ok && r.status == "completed" {
			rec = r
			break
		}
		if time.Now().After(deadline) {
			r, _ := latestRecording(t, pool)
			t.Fatalf("no completed recording in time (latest status=%q)", r.status)
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Logf("recording completed: session=%s object=%s size=%d", rec.sessionID, rec.objectKey, rec.sizeBytes)

	if auditCount(t, pool, "recording.completed") < 1 {
		t.Fatalf("expected a recording.completed audit event")
	}

	// Download the object and verify its contents + integrity.
	client := s3Client(t, silo)
	out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &silo.bucket, Key: &rec.objectKey})
	if err != nil {
		t.Fatalf("GetObject(%s): %v", rec.objectKey, err)
	}
	body, err := io.ReadAll(out.Body)
	_ = out.Body.Close()
	if err != nil {
		t.Fatalf("read recording body: %v", err)
	}

	// (a) asciicast v2: first line is a JSON header with "version":2.
	lines := bytes.Split(body, []byte("\n"))
	if len(lines) == 0 {
		t.Fatal("empty recording")
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(lines[0], &header); err != nil {
		t.Fatalf("parse asciicast header %q: %v", lines[0], err)
	}
	if header.Version != 2 {
		t.Fatalf("asciicast version = %d, want 2", header.Version)
	}

	// (b) at least one output event line carries the exec output string.
	if !containsOutputEvent(lines[1:], execCommand) {
		t.Fatalf("no ['o',...] event contained %q; recording:\n%s", execCommand, body)
	}

	// (c)+(d) the downloaded bytes match the stored digest and size exactly.
	sum := hex.EncodeToString(sha256Sum(body))
	if sum != rec.sha256 {
		t.Fatalf("sha256 mismatch: downloaded=%s stored=%s", sum, rec.sha256)
	}
	if int64(len(body)) != rec.sizeBytes {
		t.Fatalf("size mismatch: downloaded=%d stored=%d", len(body), rec.sizeBytes)
	}
	t.Logf("recording verified: asciicast v2, %d bytes, sha256=%s", len(body), sum)
}

// containsOutputEvent reports whether any asciicast event line is an output
// event (`["o", ...]` / `[t,"o",...]`) whose data contains want.
func containsOutputEvent(lines [][]byte, want string) bool {
	for _, ln := range lines {
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 || ln[0] != '[' {
			continue
		}
		var ev []json.RawMessage
		if err := json.Unmarshal(ln, &ev); err != nil {
			continue
		}
		isOutput := false
		for _, field := range ev {
			var s string
			if json.Unmarshal(field, &s) == nil && s == "o" {
				isOutput = true
				break
			}
		}
		if isOutput && strings.Contains(string(ln), want) {
			return true
		}
	}
	return false
}

// assertExemptSessionNotRecorded seeds a second user holding ssh:record:exempt on
// the asset, runs a full exec through the tunnel as that user, and asserts the
// session works but produces NO new session_recordings row (recording waived).
func assertExemptSessionNotRecorded(ctx context.Context, t *testing.T, pool *pgxpool.Pool, silo siloInfo, wardenAddr, caFile string) {
	t.Helper()

	before := recordingCount(t, pool)

	exemptToken := seedExemptUser(t, pool)

	tunnel, signer := dialWithRetryToken(ctx, t, wardenAddr, exemptToken, caFile)
	defer func() { _ = tunnel.Close() }()

	out, code, err := runExec(tunnel, login, signer, execCommand)
	if err != nil {
		t.Fatalf("exempt exec over tunnel: %v", err)
	}
	if !strings.Contains(out, execCommand) || code != 0 {
		t.Fatalf("exempt exec output=%q code=%d, want output containing %q + code 0", out, code, execCommand)
	}
	t.Logf("exempt exec round-trip OK: output=%q code=%d", strings.TrimSpace(out), code)

	// No new recording row must appear. Wait a bounded window to rule out a slow
	// upload racing in (an exempt session must never record at all).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if recordingCount(t, pool) != before {
			t.Fatalf("exempt session produced a recording row (count %d -> %d)", before, recordingCount(t, pool))
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Logf("exempt session left recording count unchanged at %d", before)
}

// assertFailClosedWhenRecordingUnavailable proves a required-recording session is
// refused when the worker cannot record. It removes the recording bucket from
// Silo so the worker's multipart-upload create fails; the worker then refuses the
// session (no bridge) and reports a failed recording. The client's exec must fail
// and a recording.failed audit must land. The bucket is recreated afterward so the
// stack is left usable for later phases.
func assertFailClosedWhenRecordingUnavailable(ctx context.Context, t *testing.T, pool *pgxpool.Pool, silo siloInfo, wardenAddr, token, caFile string) {
	t.Helper()

	client := s3Client(t, silo)
	emptyBucket(ctx, t, client, silo.bucket)
	if _, err := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &silo.bucket}); err != nil {
		t.Fatalf("delete recording bucket: %v", err)
	}
	// Restore the bucket on the way out regardless of outcome.
	defer func() {
		_, _ = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &silo.bucket})
	}()

	before := auditCount(t, pool, "recording.failed")

	// Drive the connect + exec. The worker builds the recorder BEFORE dialing the
	// target, so create_multipart_upload against the missing bucket fails: the
	// worker refuses the session (never bridges) and reports a FAILED recording to
	// warden, which audits recording.failed. The refusal means the exec never
	// receives an exit-status — it either errors or blocks — so we run it with a
	// hard deadline and treat a non-success (error OR timeout) as the refusal, with
	// the recording.failed audit as the authoritative confirmation.
	tunnel, signer := dialWithRetryToken(ctx, t, wardenAddr, token, caFile)
	defer func() { _ = tunnel.Close() }()

	execDone := make(chan error, 1)
	go func() {
		_, code, err := runExec(tunnel, login, signer, execCommand)
		if err == nil && code == 0 {
			execDone <- nil // unexpected clean success
			return
		}
		execDone <- fmt.Errorf("exec refused: err=%v code=%d", err, code)
	}()

	select {
	case err := <-execDone:
		if err == nil {
			t.Fatalf("required-recording session succeeded with the recording bucket removed (expected refusal)")
		}
		t.Logf("recording-unavailable session refused as expected: %v", err)
	case <-time.After(10 * time.Second):
		// A hung exec is itself a refusal: the worker never returned output/exit for
		// this session. The recording.failed audit below confirms the cause.
		t.Logf("recording-unavailable session did not complete (worker refused; no exit-status)")
	}

	// The authoritative signal: a recording.failed audit landed for the refused
	// session.
	auditDeadline := time.Now().Add(15 * time.Second)
	for {
		if auditCount(t, pool, "recording.failed") > before {
			t.Logf("recording.failed audit present after fail-closed refusal")
			return
		}
		if time.Now().After(auditDeadline) {
			t.Fatalf("no recording.failed audit after fail-closed refusal (before=%d now=%d)", before, auditCount(t, pool, "recording.failed"))
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// emptyBucket deletes every object in a bucket so it can be removed.
func emptyBucket(ctx context.Context, t *testing.T, client *s3.Client, bucket string) {
	t.Helper()
	lst, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
	if err != nil {
		t.Fatalf("list objects: %v", err)
	}
	for _, obj := range lst.Contents {
		key := obj.Key
		if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: key}); err != nil {
			t.Fatalf("delete object %q: %v", *key, err)
		}
	}
}

// seedExemptUser creates a user bound to ssh:login:<login> AND ssh:record:exempt
// on the same asset the deployer targets, and returns a bearer token for them.
func seedExemptUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: exemptUserEmail, DisplayName: "Exempt"})
	if err != nil {
		t.Fatalf("CreateUser(exempt): %v", err)
	}

	// Resolve the existing asset seeded by seedAccess (unique by name).
	assetID := lookupAssetID(t, pool, assetName)

	loginRole, err := q.CreateRole(ctx, sqlc.CreateRoleParams{
		Name: "ssh-deploy-exempt-login", Capabilities: capsJSON("ssh:login:" + login),
	})
	if err != nil {
		t.Fatalf("CreateRole(exempt login): %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: loginRole.ID, ScopeAssetID: pgUUID(assetID), SubjectUserID: pgUUID(user.ID),
	}); err != nil {
		t.Fatalf("CreateRoleBinding(exempt login): %v", err)
	}

	exemptRole, err := q.CreateRole(ctx, sqlc.CreateRoleParams{
		Name: "ssh-record-exempt", Capabilities: capsJSON("ssh:record:exempt"),
	})
	if err != nil {
		t.Fatalf("CreateRole(exempt): %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: exemptRole.ID, ScopeAssetID: pgUUID(assetID), SubjectUserID: pgUUID(user.ID),
	}); err != nil {
		t.Fatalf("CreateRoleBinding(exempt): %v", err)
	}

	tok, err := auth.NewTokenService(q).Issue(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("issue exempt token: %v", err)
	}
	return tok
}

// lookupAssetID resolves the UUID of the asset with the given name.
func lookupAssetID(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM assets WHERE name = $1`, name).Scan(&id); err != nil {
		t.Fatalf("lookup asset %q: %v", name, err)
	}
	return id
}

// dialTunnel drives a single real connect attempt (used by the fail-closed phase,
// which must observe the exec being refused rather than retry to success).
func dialTunnel(ctx context.Context, wardenAddr, token, caFile string) (net.Conn, gossh.Signer, error) {
	return clicmd.DialTunnel(ctx, wardenAddr, token, caFile, login, assetName)
}

// dialWithRetryToken is dialWithRetry with an explicit token (the base helper
// closes over the deployer token via a package const; recording phases pass their
// own token here).
func dialWithRetryToken(ctx context.Context, t *testing.T, wardenAddr, token, caFile string) (net.Conn, gossh.Signer) {
	t.Helper()
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("connect never succeeded before deadline: %v", lastErr)
		default:
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		tunnel, signer, err := clicmd.DialTunnel(attemptCtx, wardenAddr, token, caFile, login, assetName)
		cancel()
		if err == nil {
			return tunnel, signer
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
