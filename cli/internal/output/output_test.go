package output

import (
	"bytes"
	"io"
	"strings"
	"testing"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
)

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "json", map[string]any{"id": "x", "name": "n"}, nil); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, `"id": "x"`) {
		t.Fatalf("output %q does not contain %q", got, `"id": "x"`)
	}
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	tv := &Table{Headers: []string{"ID", "NAME"}, Rows: [][]string{{"x", "n"}}}
	if err := Render(&buf, "table", nil, tv); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "ID") {
		t.Fatalf("output %q does not contain %q", got, "ID")
	}
	if !strings.Contains(got, "x") {
		t.Fatalf("output %q does not contain %q", got, "x")
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Render(io.Discard, "yaml", nil, nil); err == nil {
		t.Fatalf("expected error for unknown format, got nil")
	}
}

func TestRenderProtoJSON(t *testing.T) {
	var buf bytes.Buffer
	u := &identityv1.User{Id: "u1", Email: "a@x"}
	if err := RenderProto(&buf, "json", u, nil); err != nil {
		t.Fatalf("RenderProto: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, `"u1"`) {
		t.Fatalf("output %q does not contain %q", got, `"u1"`)
	}
	if !strings.Contains(got, `"a@x"`) {
		t.Fatalf("output %q does not contain %q", got, `"a@x"`)
	}
}

func TestRenderProtoTable(t *testing.T) {
	var buf bytes.Buffer
	u := &identityv1.User{Id: "u1", Email: "a@x"}
	tv := &Table{Headers: []string{"ID"}, Rows: [][]string{{"u1"}}}
	if err := RenderProto(&buf, "table", u, tv); err != nil {
		t.Fatalf("RenderProto: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, "u1") {
		t.Fatalf("output %q does not contain %q", got, "u1")
	}
}
