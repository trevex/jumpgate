package rpc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

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
	return &catalogTestEnv{catalog: srv, adminCtx: adminCtx}
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
