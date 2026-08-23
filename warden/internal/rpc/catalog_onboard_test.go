package rpc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/rpc"
)

// catalogTestEnv is an in-process CatalogServer wired with a real pgx pool, a real
// sealer (so inline-secret sealing is exercised), and an admin-capability context.
type catalogTestEnv struct {
	catalog  *rpc.CatalogServer
	adminCtx context.Context
	pool     *pgxpool.Pool
	userID   uuid.UUID
}

// newCatalogTestEnv builds a CatalogServer over an ephemeral Postgres, seeds a
// bootstrap admin (holds ** → every management cap), and returns an env whose
// adminCtx carries that admin. The sealer is the shared test sealer so onboarding
// can seal inline login secrets.
func newCatalogTestEnv(t *testing.T) *catalogTestEnv {
	t.Helper()
	// Reuse newServer's pool + migrations; we only need the pool (the wire URL is
	// unused because we drive the server in-process).
	pool, _ := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)

	q := gen.New(pool)
	authorizer := authz.NewSQLAuthorizer(pool)
	srv := rpc.NewCatalogServer(q, pool, authorizer, nil, testSealer(t), nil)

	adminID := userID(t, pool, "admin@x")
	adminCtx := auth.WithUser(context.Background(), auth.CurrentUser{ID: adminID, Email: "admin@x"})
	return &catalogTestEnv{catalog: srv, adminCtx: adminCtx, pool: pool, userID: adminID}
}

// createFolder creates a top-level folder and returns its id.
func (e *catalogTestEnv) createFolder(t *testing.T, name string) string {
	t.Helper()
	f, err := e.catalog.CreateFolder(e.adminCtx, connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name}))
	if err != nil {
		t.Fatalf("createFolder(%q): %v", name, err)
	}
	return f.Msg.Folder.Id
}

// createChildFolder creates a folder under parentID and returns its id.
func (e *catalogTestEnv) createChildFolder(t *testing.T, name, parentID string) string {
	t.Helper()
	f, err := e.catalog.CreateFolder(e.adminCtx, connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name, ParentId: parentID}))
	if err != nil {
		t.Fatalf("createChildFolder(%q under %q): %v", name, parentID, err)
	}
	return f.Msg.Folder.Id
}

// createSSHAsset onboards an SSH asset under folderID with a ca login "deploy" and a
// password login named login carrying secret as an inline new_value; returns the id.
func (e *catalogTestEnv) createSSHAsset(t *testing.T, folderID, name, login string, secret []byte) string {
	t.Helper()
	resp, err := e.catalog.CreateAsset(e.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     name,
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			TargetAddress: "10.0.0.5:22",
			Logins: []*catalogv1.SSHLoginInput{
				{Login: "deploy", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}},
				{Login: login, Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: secret}}}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("createSSHAsset(%q): %v", name, err)
	}
	return resp.Msg.Asset.Id
}

// bindRoleToAsset inserts a role and a standing role_binding scoped to assetID with the
// seeded admin as the subject, so DeleteAsset has an asset-scoped binding to cascade.
func (e *catalogTestEnv) bindRoleToAsset(t *testing.T, assetID string) {
	t.Helper()
	var roleID string
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO roles(name) VALUES('r-'||substr(md5(random()::text),1,8)) RETURNING id`,
	).Scan(&roleID); err != nil {
		t.Fatalf("insert role: %v", err)
	}
	if _, err := e.pool.Exec(context.Background(),
		`INSERT INTO role_bindings(role_id, scope_asset_id, subject_user_id) VALUES($1, $2, $3)`,
		roleID, assetID, e.userID,
	); err != nil {
		t.Fatalf("insert role_binding: %v", err)
	}
}

// count runs a single-int aggregate query on the env pool.
func (e *catalogTestEnv) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func TestCreateAssetInlineSecretsAtomic(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")

	resp, err := env.catalog.CreateAsset(env.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     "pg",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			TargetAddress: "10.0.0.5:22",
			Logins: []*catalogv1.SSHLoginInput{
				{Login: "deploy", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}},
				{Login: "app", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
					Source: &catalogv1.SecretAuth_NewValue{NewValue: []byte("s3cr3t")}}}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	assetID := resp.Msg.Asset.Id

	got, err := env.catalog.GetAsset(env.adminCtx, connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: assetID}))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if got.Msg.Asset.Kind != "ssh" {
		t.Fatalf("kind = %q, want ssh", got.Msg.Asset.Kind)
	}
	logins := got.Msg.Asset.GetSsh().GetLogins()
	if len(logins) != 2 {
		t.Fatalf("logins = %d, want 2", len(logins))
	}
	var app *catalogv1.SSHLogin
	for _, l := range logins {
		if l.Login == "app" {
			app = l
		}
	}
	if app == nil || app.Kind != "password" || app.SecretId == "" {
		t.Fatalf("app login = %+v, want kind=password with a secret_id", app)
	}
}

func TestCreateAssetRejectsEmptyInlineSecret(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	_, err := env.catalog.CreateAsset(env.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID, Name: "pg",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{Logins: []*catalogv1.SSHLoginInput{
			{Login: "app", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
				Source: &catalogv1.SecretAuth_NewValue{NewValue: []byte{}}}}},
		}}},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument for empty new_value, got %v", err)
	}
}

func TestCreateAssetRejectsExistingSecretId(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	_, err := env.catalog.CreateAsset(env.adminCtx, connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID, Name: "pg",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{Logins: []*catalogv1.SSHLoginInput{
			{Login: "app", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
				Source: &catalogv1.SecretAuth_ExistingSecretId{ExistingSecretId: uuid.NewString()}}}},
		}}},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument for existing_secret_id on create, got %v", err)
	}
}
