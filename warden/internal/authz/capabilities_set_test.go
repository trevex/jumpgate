package authz

import (
	"slices"
	"testing"
)

func TestEntitledLoginsForPrefix(t *testing.T) {
	caps := Capabilities{"db:login:app", "db:login:readonly"}
	got := caps.EntitledLoginsFor("db:login:", []string{"app", "writer", "readonly"})
	want := []string{"app", "readonly"}
	if !slices.Equal(got, want) {
		t.Fatalf("EntitledLoginsFor(db) = %v, want %v", got, want)
	}
	// The SSH-defaulting method still works and does NOT match db caps.
	if ssh := caps.EntitledLogins([]string{"app"}); len(ssh) != 0 {
		t.Fatalf("EntitledLogins(ssh default) = %v, want empty (caps are db:)", ssh)
	}
}

func TestEntitledLoginsFor_RDP(t *testing.T) {
	caps := Capabilities{"rdp:login:administrator"}
	got := caps.EntitledLoginsFor(RDPLoginPrefix, []string{"administrator", "guest"})
	want := []string{"administrator"}
	if !slices.Equal(got, want) {
		t.Fatalf("EntitledLoginsFor(rdp) = %v, want %v", got, want)
	}
}
