package e2e

import "testing"

func TestJSONID(t *testing.T) {
	in := `{
  "id": "abc-123",
  "email": "x@y"
}`
	if got := jsonID(in); got != "abc-123" {
		t.Fatalf("jsonID = %q, want abc-123", got)
	}
	if got := jsonID(`no id here`); got != "" {
		t.Fatalf("jsonID on empty = %q, want \"\"", got)
	}
}
