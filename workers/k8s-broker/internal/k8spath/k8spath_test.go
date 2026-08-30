package k8spath

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		method, path, query      string
		verb, resource, ns, name string
	}{
		{"GET", "/api/v1/namespaces/default/pods", "", "list", "pods", "default", ""},
		{"GET", "/api/v1/namespaces/default/pods/foo", "", "get", "pods", "default", "foo"},
		{"POST", "/api/v1/namespaces/default/pods", "", "create", "pods", "default", ""},
		{"DELETE", "/api/v1/namespaces/default/pods/foo", "", "delete", "pods", "default", "foo"},
		{"GET", "/apis/apps/v1/namespaces/x/deployments", "", "list", "deployments", "x", ""},
		{"GET", "/api/v1/nodes/n1", "", "get", "nodes", "", "n1"},
		{"GET", "/api/v1/namespaces/default/pods/foo/log", "", "get", "pods", "default", "foo"},
		{"GET", "/api/v1/namespaces/default/pods", "watch=true", "watch", "pods", "default", ""},
		{"GET", "/healthz", "", "get", "", "", ""},
		{"PATCH", "/apis/apps/v1/namespaces/x/deployments/d1", "", "patch", "deployments", "x", "d1"},
	}
	for _, c := range cases {
		got := Parse(c.method, c.path, c.query)
		if got.Verb != c.verb || got.Resource != c.resource || got.Namespace != c.ns || got.Name != c.name {
			t.Errorf("Parse(%s %s?%s) = %+v; want verb=%s resource=%s ns=%s name=%s",
				c.method, c.path, c.query, got, c.verb, c.resource, c.ns, c.name)
		}
	}
}
