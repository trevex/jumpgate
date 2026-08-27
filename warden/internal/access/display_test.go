package access_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// TestListRoleBindingsDenormalized proves ListRoleBindings returns resolved subject
// name + kind + role name for a bound group.
func TestListRoleBindingsDenormalized(t *testing.T) {
	f := setupCascade(t)
	ctx, q := f.ctx, f.q

	roleID := uuid.MustParse(f.createRole(t, "db-reader"))
	grp, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "sre-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:         roleID,
		ScopeAssetID:   pgtype.UUID{Bytes: f.asset, Valid: true},
		SubjectGroupID: pgtype.UUID{Bytes: grp.ID, Valid: true},
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	resp, err := f.acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{
		RoleId: roleID.String(), PageSize: 50,
	}), f.admin))
	if err != nil {
		t.Fatalf("ListRoleBindings: %v", err)
	}
	var got *accessv1.RoleBinding
	for _, b := range resp.Msg.Bindings {
		if b.SubjectGroupId == grp.ID.String() {
			got = b
		}
	}
	if got == nil {
		t.Fatalf("binding for group not returned")
	}
	if got.SubjectKind != "group" || got.SubjectDisplayName != grp.Name {
		t.Fatalf("bad denormalized fields: kind=%q name=%q", got.SubjectKind, got.SubjectDisplayName)
	}
	if got.RoleName != "db-reader" {
		t.Fatalf("bad role name: %q", got.RoleName)
	}
}
