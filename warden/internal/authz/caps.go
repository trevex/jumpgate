package authz

// Capability vocabulary: the single home for the concrete capability strings used
// at authz call sites. Bare string literals for these MUST NOT appear elsewhere —
// a rename is then one compiler-checked edit, not a grep across packages. Glob
// semantics are unchanged; these are just the concrete names the Guard checks.
//
// The subtree-wide read broadening FolderReadCap lives in capabilities_set.go
// (next to ReadAllowed, which consumes it).
const (
	// Object-read capabilities (per object kind).
	AssetReadCap = "catalog:asset:read"
	RoleReadCap  = "access:role:read"
	GroupReadCap = "identity:group:read"

	// Folder authoring/read.
	FolderCreateCap = "catalog:folder:create"

	// Access-model reads.
	BindingReadCap = "access:binding:read"

	// Session-review / recordings.
	RecordingReadCap = "recording:read"
)
