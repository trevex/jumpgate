// Package k8spath parses a Kubernetes API request path into audit metadata. It is
// a miniature of the apiserver's RequestInfo logic — enough for the audit line
// {verb, resource, namespace, name}, not a full RBAC decision.
//
// ponytail: handles the /api (core) vs /apis (named group) offset, cluster-scoped
// resources (no namespaces/ segment), subresources (mapped to their parent), and
// watch. Not exhaustive (no proxy/api-versions edge paths) — extend if the audit
// needs them.
package k8spath

import "strings"

// Info is the parsed audit metadata for one API request.
type Info struct {
	Verb      string
	Resource  string
	Namespace string
	Name      string
}

// Parse derives audit metadata from the HTTP method, URL path, and raw query.
func Parse(method, path, rawQuery string) Info {
	watch := strings.Contains(rawQuery, "watch=true") || strings.Contains(rawQuery, "watch=1")
	segs := strings.Split(strings.Trim(path, "/"), "/")

	var i int
	switch {
	case len(segs) >= 2 && segs[0] == "api":
		i = 2
	case len(segs) >= 3 && segs[0] == "apis":
		i = 3
	default:
		// Non-API paths (/healthz, /livez, ...) address a single endpoint, not a
		// collection, so treat them as "get" rather than "list".
		return Info{Verb: verbFor(method, true, watch)}
	}

	var info Info
	rest := segs[i:]
	if len(rest) >= 2 && rest[0] == "namespaces" {
		if len(rest) == 2 {
			info.Resource, info.Name = "namespaces", rest[1]
			info.Verb = verbFor(method, info.Name != "", watch)
			return info
		}
		info.Namespace = rest[1]
		rest = rest[2:]
	}
	if len(rest) == 0 {
		return Info{Verb: verbFor(method, false, watch)}
	}
	info.Resource = rest[0]
	if len(rest) >= 2 {
		info.Name = rest[1]
	}
	info.Verb = verbFor(method, info.Name != "", watch)
	return info
}

func verbFor(method string, hasName, watch bool) string {
	if watch {
		return "watch"
	}
	switch method {
	case "POST":
		return "create"
	case "PUT":
		return "update"
	case "PATCH":
		return "patch"
	case "DELETE":
		return "delete"
	default:
		if hasName {
			return "get"
		}
		return "list"
	}
}
