//nolint:revive // Compatibility aliases are documented by the public package.
package authz

import publicauthz "github.com/trevex/jumpgate/warden/authz"

// Keep the implementation package source-compatible while callers migrate to
// the public authorization contracts. These are aliases, so the PostgreSQL
// implementation satisfies publicauthz.Authorizer without adapters.
type (
	Authorizer      = publicauthz.Authorizer
	AssetVisibility = publicauthz.AssetVisibility
	AssetRoles      = publicauthz.AssetRoles
	VisibleFolder   = publicauthz.VisibleFolder
	Capabilities    = publicauthz.Capabilities
	ScopeKind       = publicauthz.ScopeKind
	Scope           = publicauthz.Scope
)

const (
	ScopeGlobal = publicauthz.ScopeGlobal
	ScopeFolder = publicauthz.ScopeFolder
	ScopeAsset  = publicauthz.ScopeAsset
)

var (
	CapMatch       = publicauthz.CapMatch
	Covers         = publicauthz.Covers
	NormalizeCap   = publicauthz.NormalizeCap
	ReconstructCap = publicauthz.ReconstructCap
	GlobalScope    = publicauthz.GlobalScope
	FolderScope    = publicauthz.FolderScope
	AssetScope     = publicauthz.AssetScope
)
