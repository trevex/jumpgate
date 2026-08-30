package authz

import (
	"reflect"
	"testing"
)

func TestConcreteQualifiers(t *testing.T) {
	cases := []struct {
		name string
		held []string
		want []string
	}{
		{"concrete groups", []string{"k8s:group:developers", "k8s:group:oncall"}, []string{"developers", "oncall"}},
		{"colon group kept whole", []string{"k8s:group:system:masters"}, []string{"system:masters"}},
		{"wildcards skipped", []string{"k8s:group:*", "k8s:group:**", "**", "k8s:**"}, nil},
		{"mixed", []string{"k8s:group:dev", "k8s:group:*", "db:login:app"}, []string{"dev"}},
		{"dedup", []string{"k8s:group:dev", "k8s:group:dev"}, []string{"dev"}},
		{"empty qualifier skipped", []string{"k8s:group:"}, nil},
		{"none", []string{"db:login:app", "ssh:login:root"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Capabilities(tc.held).ConcreteQualifiers(K8sGroupPrefix)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ConcreteQualifiers(%v) = %v, want %v", tc.held, got, tc.want)
			}
		})
	}
}

// Colon groups must be distinguishable through CapMatch (the concrete-match path),
// so an admin granting system:masters never accidentally grants system:foo.
func TestCapMatchColonGroupDistinct(t *testing.T) {
	if !CapMatch("k8s:group:system:masters", "k8s:group:system:masters") {
		t.Fatal("exact colon group should match")
	}
	if CapMatch("k8s:group:system:masters", "k8s:group:system:foo") {
		t.Fatal("distinct colon groups must not match")
	}
	if !CapMatch("k8s:group:**", "k8s:group:system:masters") {
		t.Fatal("k8s:group:** should match a colon group")
	}
	if CapMatch("k8s:group:*", "k8s:group:system:masters") {
		t.Fatal("single * must not span a colon group (two segments)")
	}
}
