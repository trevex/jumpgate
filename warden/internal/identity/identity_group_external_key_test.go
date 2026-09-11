package identity_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

// queryGroupExternalKey reads a group's stored external_key directly (bypassing
// the API), returning "" for NULL, so tests can assert on the persisted DB state
// independent of the proto round-trip.
func queryGroupExternalKey(t *testing.T, pool *pgxpool.Pool, groupID string) string {
	t.Helper()
	var key *string
	if err := pool.QueryRow(context.Background(), `SELECT external_key FROM groups WHERE id=$1`, groupID).Scan(&key); err != nil {
		t.Fatalf("query external_key: %v", err)
	}
	if key == nil {
		return ""
	}
	return *key
}

// TestGroupExternalKey covers the write surface for groups.external_key: set on
// create, round-trips on read, settable/clearable via SetGroupExternalKey, and
// duplicate keys are rejected (AlreadyExists) on both paths.
func TestGroupExternalKey(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Set on create; round-trips both in the response and in the DB.
	g1, err := c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
		Name: "grp1", ExternalKey: "idp-grp-1",
	}), tok))
	if err != nil {
		t.Fatalf("create group1: %v", err)
	}
	if g1.Msg.Group.ExternalKey != "idp-grp-1" {
		t.Fatalf("create response external_key = %q, want idp-grp-1", g1.Msg.Group.ExternalKey)
	}
	if got := queryGroupExternalKey(t, pool, g1.Msg.Group.Id); got != "idp-grp-1" {
		t.Fatalf("db external_key = %q, want idp-grp-1", got)
	}
	if got := readGroupExternalKeyViaList(ctx, t, c, tok, g1.Msg.Group.Id); got != "idp-grp-1" {
		t.Fatalf("ListGroups external_key = %q, want idp-grp-1", got)
	}

	// A group created with no external_key stays unmapped (NULL, empty on the wire).
	g2, err := c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "grp2"}), tok))
	if err != nil {
		t.Fatalf("create group2: %v", err)
	}
	if g2.Msg.Group.ExternalKey != "" {
		t.Fatalf("create response external_key = %q, want empty", g2.Msg.Group.ExternalKey)
	}

	// SetGroupExternalKey sets it, then clears it with "".
	if _, err := c.SetGroupExternalKey(ctx, withToken(connect.NewRequest(&identityv1.SetGroupExternalKeyRequest{
		GroupId: g2.Msg.Group.Id, ExternalKey: "idp-grp-2",
	}), tok)); err != nil {
		t.Fatalf("set external key: %v", err)
	}
	if got := queryGroupExternalKey(t, pool, g2.Msg.Group.Id); got != "idp-grp-2" {
		t.Fatalf("db external_key after set = %q, want idp-grp-2", got)
	}

	// Setting the SAME key on the SAME group again is idempotent, not a
	// self-collision against its own existing value.
	if _, err := c.SetGroupExternalKey(ctx, withToken(connect.NewRequest(&identityv1.SetGroupExternalKeyRequest{
		GroupId: g2.Msg.Group.Id, ExternalKey: "idp-grp-2",
	}), tok)); err != nil {
		t.Fatalf("re-set same external key: %v", err)
	}

	if _, err := c.SetGroupExternalKey(ctx, withToken(connect.NewRequest(&identityv1.SetGroupExternalKeyRequest{
		GroupId: g2.Msg.Group.Id, ExternalKey: "",
	}), tok)); err != nil {
		t.Fatalf("clear external key: %v", err)
	}
	if got := queryGroupExternalKey(t, pool, g2.Msg.Group.Id); got != "" {
		t.Fatalf("db external_key after clear = %q, want empty (NULL)", got)
	}

	// Clearing an already-unset key is a no-op, not an error.
	if _, err := c.SetGroupExternalKey(ctx, withToken(connect.NewRequest(&identityv1.SetGroupExternalKeyRequest{
		GroupId: g2.Msg.Group.Id, ExternalKey: "",
	}), tok)); err != nil {
		t.Fatalf("clear already-unset external key: %v", err)
	}

	// Duplicate external_key on CreateGroup is rejected.
	_, err = c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
		Name: "grp3", ExternalKey: "idp-grp-1",
	}), tok))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate external_key on create code = %v, want AlreadyExists", connect.CodeOf(err))
	}

	// Duplicate external_key on SetGroupExternalKey is rejected.
	_, err = c.SetGroupExternalKey(ctx, withToken(connect.NewRequest(&identityv1.SetGroupExternalKeyRequest{
		GroupId: g2.Msg.Group.Id, ExternalKey: "idp-grp-1",
	}), tok))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate external_key on set code = %v, want AlreadyExists", connect.CodeOf(err))
	}

	// A capless caller is denied.
	seedUser(t, pool, "user@x", "password123456", false)
	uc := authClient(t, url, "user@x", "password123456")
	_, err = c.SetGroupExternalKey(ctx, withToken(connect.NewRequest(&identityv1.SetGroupExternalKeyRequest{
		GroupId: g1.Msg.Group.Id, ExternalKey: "nope",
	}), uc))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin SetGroupExternalKey code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// A caller holding ONLY identity:group:create (not set-external-key) may create
	// plain groups but is denied setting external_key at creation time — otherwise
	// the dedicated cap would be trivially bypassable via the create path.
	seedCapUser(t, pool, "creator@x", "password123456", `["identity:group:create"]`)
	cc := authClient(t, url, "creator@x", "password123456")
	if _, err := c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
		Name: "plain-ok",
	}), cc)); err != nil {
		t.Fatalf("create-cap caller creating a plain group: %v", err)
	}
	_, err = c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
		Name: "with-key", ExternalKey: "sneaky",
	}), cc))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("create-cap-only caller creating with external_key code = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// readGroupExternalKeyViaList finds groupID in a ListGroups page and returns its
// external_key, proving the field round-trips through the list-read path too.
func readGroupExternalKeyViaList(ctx context.Context, t *testing.T, c identityv1connect.IdentityServiceClient, tok string, groupID string) string {
	t.Helper()
	groups, err := c.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	for _, g := range groups.Msg.Groups {
		if g.Id == groupID {
			return g.ExternalKey
		}
	}
	t.Fatalf("group %s not found in ListGroups", groupID)
	return ""
}
