package access

// SubjectView is the resolved display for a (user XOR group) subject. Its fields are
// populated directly from fully-resolved SQL read rows (see roster.go) — there is no
// per-row Go resolution.
type SubjectView struct {
	Kind        string // "user" | "group"
	DisplayName string
	FolderPath  string // group home; empty for users
	MemberCount int32  // 0 for users
	Active      bool   // user active; true for groups
}
