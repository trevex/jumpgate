package dataplane

import "testing"

func TestRecordingFormat(t *testing.T) {
	cases := map[string]string{
		"ssh":      "asciicast-v2",
		"postgres": "pgwire-timeline-v1",
		"":         "asciicast-v2", // legacy/empty defaults to ssh format
	}
	for proto, want := range cases {
		if got := recordingFormat(proto); got != want {
			t.Errorf("recordingFormat(%q) = %q, want %q", proto, got, want)
		}
	}
}
