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

	// catalog:asset authoring.
	AssetCreateCap = "catalog:asset:create"
	AssetUpdateCap = "catalog:asset:update"
	AssetDeleteCap = "catalog:asset:delete"

	// catalog:folder authoring/read.
	FolderCreateCap = "catalog:folder:create"
	FolderUpdateCap = "catalog:folder:update"
	FolderDeleteCap = "catalog:folder:delete"

	// access:role authoring.
	RoleCreateCap = "access:role:create"
	RoleUpdateCap = "access:role:update"
	RoleDeleteCap = "access:role:delete"

	// access:policy authoring/read.
	PolicyReadCap           = "access:policy:read"
	PolicyCreateCap         = "access:policy:create"
	PolicyUpdateCap         = "access:policy:update"
	PolicyDeleteCap         = "access:policy:delete"
	PolicyManageSubjectsCap = "access:policy:manage-subjects"

	// Access-model reads/authoring.
	BindingReadCap   = "access:binding:read"
	BindingCreateCap = "access:binding:create"
	BindingDeleteCap = "access:binding:delete"

	// identity:user authoring/read.
	UserReadCap       = "identity:user:read"
	UserCreateCap     = "identity:user:create"
	UserDeleteCap     = "identity:user:delete"
	UserDeactivateCap = "identity:user:deactivate"

	// identity:group authoring.
	GroupCreateCap       = "identity:group:create"
	GroupDeleteCap       = "identity:group:delete"
	GroupAddMemberCap    = "identity:group:add-member"
	GroupRemoveMemberCap = "identity:group:remove-member"

	// Session-review / recordings.
	RecordingReadCap = "recording:read"
)
