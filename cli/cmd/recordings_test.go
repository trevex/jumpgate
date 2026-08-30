package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	recordingv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1/recordingv1connect"
)

type stubRecording struct {
	recordingv1connect.UnimplementedRecordingServiceHandler
	gotList     *recordingv1.ListRecordingsRequest
	downloadURL string
}

func (s *stubRecording) ListRecordings(_ context.Context, req *connect.Request[recordingv1.ListRecordingsRequest]) (*connect.Response[recordingv1.ListRecordingsResponse], error) {
	s.gotList = req.Msg
	return connect.NewResponse(&recordingv1.ListRecordingsResponse{Recordings: []*recordingv1.Recording{
		{
			SessionId: "s1",
			UserId:    "u1",
			AssetId:   "a1",
			Protocol:  "ssh",
			Format:    "asciicast",
			SizeBytes: 4096,
			Sha256:    "deadbeefcafef00d0000000000000000",
			Status:    "complete",
		},
	}}), nil
}

func (s *stubRecording) GetRecording(_ context.Context, req *connect.Request[recordingv1.GetRecordingRequest]) (*connect.Response[recordingv1.Recording], error) {
	return connect.NewResponse(&recordingv1.Recording{
		SessionId: req.Msg.GetSessionId(),
		UserId:    "u1",
		AssetId:   "a1",
		Protocol:  "ssh",
		Format:    "asciicast",
		SizeBytes: 4096,
		Sha256:    "deadbeefcafef00d0000000000000000",
		Status:    "complete",
	}), nil
}

func (s *stubRecording) GetRecordingDownload(_ context.Context, _ *connect.Request[recordingv1.GetRecordingRequest]) (*connect.Response[recordingv1.GetRecordingDownloadResponse], error) {
	return connect.NewResponse(&recordingv1.GetRecordingDownloadResponse{
		Url:             s.downloadURL,
		ExpiresAtUnixMs: 1,
	}), nil
}

// newRecordingStub starts an httptest server serving the given recording handler
// and returns its base URL.
func newRecordingStub(t *testing.T, h recordingv1connect.RecordingServiceHandler) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(recordingv1connect.NewRecordingServiceHandler(h))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRecordingsList(t *testing.T) {
	s := &stubRecording{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newRecordingStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"recordings", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "s1") || !strings.Contains(got, "ssh") || !strings.Contains(got, "complete") {
		t.Fatalf("out=%s", got)
	}
	// sha256 rendered short.
	if !strings.Contains(got, "deadbeef") {
		t.Fatalf("expected short sha256 in out=%s", got)
	}
}

func TestRecordingsGet(t *testing.T) {
	t.Setenv("JUMPGATE_WARDEN_ADDR", newRecordingStub(t, &stubRecording{}))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"recordings", "get", "s1", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "s1") || !strings.Contains(got, "asciicast") {
		t.Fatalf("out=%s", got)
	}
}

func TestRecordingsDownload(t *testing.T) {
	const canned = "{\"version\": 2, \"width\": 80, \"height\": 24}\n"
	blob := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(canned))
	}))
	t.Cleanup(blob.Close)

	s := &stubRecording{downloadURL: blob.URL}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newRecordingStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	dir := t.TempDir()
	out := filepath.Join(dir, "rec.cast")

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"recordings", "download", "s1", "-f", out})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	t.Cleanup(func() { recordingsDownloadFile = "" })

	b, err := os.ReadFile(out) // #nosec G304 -- out is a test-controlled temp path
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(b) != canned {
		t.Fatalf("file=%q want=%q", string(b), canned)
	}
	if !strings.Contains(buf.String(), out) {
		t.Fatalf("expected written path in out=%s", buf.String())
	}
	if !strings.Contains(buf.String(), "asciinema play") {
		t.Fatalf("expected replay hint in out=%s", buf.String())
	}
}

func TestRecordingSuffix(t *testing.T) {
	cases := map[string]string{
		"pgwire-timeline-v1": ".ndjson",
		"asciicast-v2":       ".cast",
		"":                   ".cast",
	}
	for format, want := range cases {
		if got := recordingSuffix(format); got != want {
			t.Errorf("recordingSuffix(%q) = %q, want %q", format, got, want)
		}
	}
}

func TestReplayHint(t *testing.T) {
	if h := replayHint("pgwire-timeline-v1", "s.ndjson"); !strings.Contains(h, "jq") || strings.Contains(h, "asciinema") {
		t.Errorf("postgres hint = %q, want a jq/console hint (no asciinema)", h)
	}
	if h := replayHint("asciicast-v2", "s.cast"); !strings.Contains(h, "asciinema") {
		t.Errorf("asciicast hint = %q, want asciinema", h)
	}
}
